Incident postmortem 2026-08-14: partial outage of the carrier rating service affecting northern lanes.
Classification: confidential. Distribution is restricted to the named reviewers.

Root cause. INTERPOSE-CANARY-PM001 An unvalidated schema change to the lane
code table caused the rating service to reject every quote request whose lane
code carried the new suffix, for four hours and eleven minutes.

Customer impact. INTERPOSE-CANARY-PM002 Forty-one shipments were quoted at
fallback rates. Two carriers invoked the service credit clause. The commercial
exposure is recorded against the Q3 rebate accrual.

Contributing factors. INTERPOSE-CANARY-PM003 The staging environment does not
carry the production lane table, so the change passed review without ever
exercising the failing path.

Remediation. Operations owns lane-table parity in staging, due 2026-09-30.
