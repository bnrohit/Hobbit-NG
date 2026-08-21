# Hobbit-NG Operations Guide

This guide describes a conservative recurring-security workflow for environments where you have explicit authorization to assess the configured targets.

## Recommended operating model

1. Create a site-specific configuration with an enforced target allowlist.
2. Start with `quick` scan depth and a small subnet.
3. Verify the resulting asset inventory against the expected inventory.
4. Save a known-good report as the baseline.
5. Run recurring scans after maintenance windows or on an approved schedule.
6. Review drift before updating the baseline.
7. Update the baseline only after the change is understood and accepted.

## Change-control example

Before a network or server change:

```bash
python hobbit.py -t 10.20.0.0/24 --ack-authorized --save-baseline baselines/pre-change.json
```

After the change:

```bash
python hobbit.py \
  -t 10.20.0.0/24 \
  --ack-authorized \
  --baseline baselines/pre-change.json \
  --fail-on-regression \
  -o reports/post-change.json
```

A non-zero regression result should be reviewed rather than automatically accepted. Common legitimate causes include a newly deployed server, a newly published service, or a planned firewall change.

## What to review first

Prioritize:

1. New medium/high/critical findings.
2. Newly opened management or data-service ports.
3. New assets not present in the approved inventory.
4. Assets whose exposure score increased materially.
5. Scan errors that could hide coverage gaps.
6. Resolved findings to verify remediation succeeded.

## Baseline hygiene

Do not automatically overwrite yesterday's baseline with today's scan. A baseline should represent an approved state. Keep dated reports for auditability and only promote a report to baseline after reviewing drift.

## Target policy

Production deployments should enable `target_policy.enforce_allowlist`. Use narrow CIDRs and explicit hostname patterns. Deny subnets that should never be actively assessed from Hobbit-NG, even if they are numerically inside a broader allowed range.

## Performance and safety

`max_concurrent_tasks`, `max_hosts_parallel`, `max_hosts_per_target`, and `max_total_hosts` are safety controls. Increase them only after measuring impact in a lab and confirming the target environment can tolerate the additional connection rate.

## Interpreting findings

Hobbit-NG exposure findings indicate observed reachability, not proof of exploitability. For example, a reachable database port means the TCP service accepted a connection; it does not mean authentication is bypassable. Treat these observations as prompts for configuration review and segmentation validation.
