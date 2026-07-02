# Vulnerable: hardcoded AWS access key ID (CWE-798).
#
# Uses AWS's canonical documentation example key so this fixture is not a live
# credential (and is not blocked by push-protection secret scanning), while
# still matching Godzilla's AWS access-key detector. The scanner must find it
# even though it is a module-level constant referenced only from another
# function — the regression this sample guards.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


def connect():
    print(AWS_ACCESS_KEY_ID)
