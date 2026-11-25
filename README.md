# Lab 1: Brute-Force Detection on Windows Security Events (KQL)

**Environment:** Active Directory lab (`DC01` domain controller, `CLIENT01` workstation).
Events exported from `DC01` with PowerShell and loaded into a free Azure Data Explorer cluster as a table with the same shape as Sentinel's `SecurityEvent`.
**Note:** In the free cluster my table is called `SecurityEvents`. In Microsoft Sentinel the table is `SecurityEvent`. Rename it when moving the query.

**Skills shown:** KQL (`summarize`, `countif`, `minif`, `maxif`, `datetime_diff`, `bin`), Kerberos event analysis (4771, 4624), threshold tuning, reasoning about false negatives.

---

## 1. Goal

Detect two things from Windows Security events:

1. **Brute force:** many failed password attempts against an account in a short time.
2. **Brute force that succeeded:** an account with many failures and then a successful logon.

## 2. Events used

| EventID | Meaning | Used for |
|---|---|---|
| 4771 | Kerberos pre-authentication failed | Failed attempts |
| 4624 | Successful logon | Success after failures |

`Status == "0x18"` on a 4771 event means a **wrong password**. Other statuses (for example `0x6` unknown user, `0x12` disabled/locked account) are different problems, so I filter to `0x18` for brute force.

## 3. How I generated the data

- ~6 wrong passwords at the `CLIENT01` login screen against `npatel` (Windows slowed me down after a few attempts).
- A loop of 8 wrong passwords against `npatel` from a script. **The source IP was `::1` (loopback), so the script ran on `DC01` itself, not `CLIENT01`.** That matters in a real investigation and is a limitation of this lab.
- 2 wrong passwords against a second test account (`User`), to check that a low-volume account does *not* trigger.
- One correct login as `npatel` afterwards.

## 4. Detection 1: failures per account, per 5-minute bin

```kusto
SecurityEvent
| where EventID == 4771 and Status == "0x18"
| summarize Failures = count() by TargetUserName, IpAddress, bin(TimeGenerated, 5m)
| where Failures >= 5
```

Result with **no threshold** (all bins):

| IpAddress | TargetUserName | Bin | Failures |
|---|---|---|---|
| ::ffff:192.168.1.99 | npatel | 12:00 | 1 |
| ::1 | User | 12:15 | 2 |
| ::ffff:192.168.1.99 | npatel | 12:20 | 1 |
| ::ffff:192.168.1.99 | npatel | 12:30 | **6** |
| ::1 | npatel | 12:35 | **8** |

**Threshold tuning**

| Threshold | Rows returned | Comment |
|---|---|---|
| `>= 5` | the two `npatel` bursts (6 and 8) | Catches the attack, ignores `User` (2) and isolated single failures |
| `>= 2` | adds `User` (2 failures) | More coverage, but more noise. Typing a password wrong twice is normal |

I chose **5**. Real users mistype once or twice; five in five minutes is unusual.

**Finding:** the attack on `npatel` appears as **two rows from two different sources** (`::ffff:192.168.1.99` and `::1`). Grouping by IP means an attacker spreading attempts across several sources, each under the threshold, would be missed. This is a limitation of grouping by IP. Grouping by account only would catch it.

## 5. Detection 2: brute force followed by success (final query)

```kusto
SecurityEvent
| where EventID in (4771, 4624)
| summarize
    Failure       = countif(EventID == 4771 and Status == "0x18"),
    First_failure = minif(TimeGenerated, EventID == 4771 and Status == "0x18"),
    Last_success  = maxif(TimeGenerated, EventID == 4624),
    Last_failure  = maxif(TimeGenerated, EventID == 4771 and Status == "0x18")
    by TargetUserName
| extend Gap = datetime_diff("second", Last_success, Last_failure)
| where Failure >= 5 and Last_success > First_failure and abs(Gap) <= 900
```

**How it works**

- One row per account, with all its 4771 and 4624 events collected.
- `countif / minif / maxif` calculate failure and success facts in a single pass.
- `datetime_diff("second", later, earlier)` gives the gap in seconds. Later time goes first.
- `Last_success > First_failure` means the success came after the attack started.
- `abs(Gap) <= 900` means the last failure and last success are within 15 minutes of each other.

**Result**

| TargetUserName | Failure | First_failure | Last_success | Last_failure | Gap |
|---|---|---|---|---|---|
| npatel | 16 | 12:03:44 | 12:37:25 | 12:38:59 | **-94** |

Only `npatel` was returned. `User` (2 failures, no success) was correctly left out.

### Why the gap is negative, and why that matters

The last failure (12:38:59) came **94 seconds after** the last success (12:37:25). My first version used `Gap > 0`, which would have **discarded this account**. A reader pointed out on LinkedIn that brute-force tools often send attempts in threads, so a few failures can arrive after a successful login. I fixed it by using `abs(Gap)`.

**Honest note on the cause in my lab:** the success at 12:37:25 came from `CLIENT01` (`192.168.1.99`), while my script on `DC01` (`::1`) was still sending failures until 12:38:59. So the negative gap here comes from two overlapping sources, not from a threaded tool's stragglers. The effect on the query is the same (failures arrive after the latest success), and `abs(Gap)` handles it, but I have not reproduced the exact threaded-tool case from the comment.

### Noise in the success events (4624)

The dataset contained 628 successful logons against 18 failed Kerberos pre-authentications, about 35 to 1. Breaking the 4624 events down by `LogonType` and by machine account (`TargetUserName` ending in `$`):

| LogonType | Machine account (`$`) | Logons | Share | What it is |
|---|---|---|---|---|
| 3 (network) | yes | 303 | 48% | `DC01` and `CLIENT01` authenticating to each other |
| 5 (service) | no | 278 | 44% | Windows services starting under service accounts |
| 2 (interactive) | no | 32 | 5% | Local sign-ins |
| 3 (network) | no | 11 | 2% | All 11 belong to `npatel` (my test account) |
| 0 (system) | no | 4 | 1% | System logons |

Machine accounts and service logons together are **581 of 628 (about 93%)**, so most "successes" are background noise. Only 43 events (types 2 and 3 from non-machine accounts) look like user activity, and 11 of those are `npatel`.

`npatel`'s 11 successful events were all **LogonType 3 (network)**, in three episodes (12:24:58, 12:32:45 and 12:37:25) of 2 to 5 events each. One network logon produces several 4624 events in the same second, so the event count is larger than the number of logons. Two of them at 12:24:58 have no source IP (`-`), so grouping by IP on 4624 would split an account's events across rows.

**Why the detection still worked:** it requires `Failure >= 5` before it considers any success, so the 628 successes are discarded for every account without failures. It would not protect against an account that has 5 or more old failures and then any unrelated background logon.

**Two filters a production version would add:**

1. `TargetUserName !endswith "$"` removes machine accounts (303 events). It does **not** remove the 278 service logons, because service accounts such as `SYSTEM` don't end in `$`.
2. Restrict the logon type, for example `tostring(LogonType) in ("2", "3", "10")`, to drop service (5) and system (0) logons.

Together these would cut 628 events down to the 43 that look like user activity.

## 6. Why 16 failures, and not "16 in 15 minutes"?

The 16 is every `npatel` failure in the whole export, added up: 1 (12:00 bin) + 1 (12:20 bin) + 6 (12:30 bin) + 8 (12:35 bin) = 16. The failures span about **35 minutes** (12:03 to 12:38).

The 900-second check does **not** limit the attack to 15 minutes. It only compares the last failure with the last success. The query has **no time window on the failure count**. This is the main limitation of the final query.

## 7. Why I did not use `bin()` in the final query

I tried `by TargetUserName, bin(TimeGenerated, 15m)` to force a 15-minute window. It is a reasonable idea, and it does limit each count to a window. I did not keep it for three reasons:

1. **Fixed bin boundaries cause missed detections.** Bins are fixed (12:15 to 12:30, 12:30 to 12:45, ...), not sliding. If failures land at 12:28 and the success at 12:32, they fall into different bins, and the account is missed. The straggler problem from section 5 can also be split by a boundary.
2. **The gap check becomes redundant.** Everything inside a 15-minute bin is less than 900 seconds apart, so `abs(Gap) <= 900` is always true and no longer filters anything.
3. **Per-bin counts hide the whole attack.** A slow attack spread over several bins could stay under the threshold in each one.

So `bin()` is not wrong. It is a trade-off, and for this query I chose whole-account aggregation and accepted its limitation.

## 8. What to use instead of `bin()` for the time window

| Approach | How | Trade-off |
|---|---|---|
| **Limit the lookback in the rule (my choice)** | Keep the query without `bin`. In a Sentinel scheduled analytics rule, set "Run query every" to 5 minutes and "Look up data from the last" to 15 minutes to 1 hour | The platform bounds the window, rules overlap, so boundaries matter much less. Needs Sentinel, not just ADX |
| **`ago()` in the query** | `where TimeGenerated > ago(1h)` as the first filter | Simple. In ADX or Log Analytics it limits the whole query, not each attack |
| **Overlapping windows** | Run the query more often than the window length (for example every 5 minutes over the last 15) | Reduces missed attacks at boundaries |
| **Session windows (stretch, not tested in this lab)** | `row_window_session()` groups sorted events into sessions with a maximum length, so windows follow the data and not the clock | Better logic, harder to read. Needs sorted data (`serialize`) |

I would use **the lookback approach** when moving this to a Sentinel analytics rule.

## 9. Limitations (honest list)

- The scripted attack came from `::1`, so it ran on `DC01` itself and does not look like a real remote attacker.
- Failures are not time-windowed in the final query (sections 6 to 8).
- Grouping by IP in Detection 1 can miss distributed attacks.
- The final query does not filter machine accounts or logon type on 4624. Here that is harmless because of the `Failure >= 5` condition, but about 93% of the successful logons in this dataset were machine or service noise, so on real data it is a false-positive risk (see the noise subsection in section 5).
- Tiny dataset (my own lab, one attack). Thresholds are not validated against normal production traffic.
- Run in a free ADX cluster, not Sentinel, so the agent and ingestion side was not exercised.

## 10. What I learned

- Reading raw events before filtering (`IpAddress` format, `Status` codes).
- Counting and timing in one pass with `countif`, `minif`, `maxif`.
- `datetime_diff` argument order, and what a negative gap means.
- Good detections have documented limits. A fix can introduce a new weakness (`bin`), so test it against the data.

## 11. Screenshots to include (crop out cluster URL, account and tenant names)

| # | What to capture | Shows |
|---|---|---|
| 1 | `SecurityEvents \| where EventID == 4771 \| take 5` | Raw data, `IpAddress` format, `Status` |
| 2 | `summarize Events = count() by EventID` | 4624 = 628 and 4771 = 18 |
| 3 | Detection 1 with **no** threshold line | All bins (1, 2, 1, 6, 8) |
| 3b | Failures per minute for `npatel`, `render columnchart` | The burst, visually |
| 3c | Seconds between attempts (`prev()` and `datetime_diff`) | Machine-speed attempts versus manual typing |
| 4 | Detection 1 with `Failures >= 5` | The two attack rows only |
| 5 | Detection 1 with `Failures >= 2` | `User` appears: threshold tuning |
| 6 | The 16-row timeline (`TargetUserName == "npatel"`, `order by TimeGenerated asc`) | Evidence for why the count is 16 and not "16 in 15 minutes" |
| 7 | Final query with its result, `-94` row visible | Failures arriving after the latest success |
| 8 | 4624 grouped by `LogonType` and machine account | The noise breakdown (303 / 278 / 32 / 11 / 4) |
| 9 | `npatel`'s own 4624 events | 11 events, all LogonType 3, three episodes |
| 10 | *(optional)* the 15-minute `bin` version and its result | The comparison in section 7 |

## 12. Files in this repo

- `kql/bruteforce-all-accounts.kql`: Detection 1
- `kql/bruteforce-then-success.kql`: Detection 2 (final)
- `screenshots/`: the images above
