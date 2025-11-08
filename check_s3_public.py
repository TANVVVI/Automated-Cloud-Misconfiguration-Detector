import boto3
import json
import sys
import traceback
from botocore.exceptions import (
    NoCredentialsError,
    PartialCredentialsError,
    ClientError,
)

def analyze_s3_buckets():
    """
    Checks all S3 buckets for public access permissions.
    Returns a list of findings.
    """
    results = []

    try:
        # Initialize S3 client (reads from environment variables or ~/.aws/credentials)
        s3 = boto3.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])

        if not buckets:
            results.append({"bucket": None, "issue": "No buckets found", "permission": "N/A"})
            return results

        # Loop through each bucket and inspect ACL
        for bucket in buckets:
            name = bucket.get("Name")
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                grants = acl.get("Grants", [])
                public = False
                for g in grants:
                    grantee = g.get("Grantee", {})
                    if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                        public = True
                        results.append({
                            "bucket": name,
                            "issue": "Public Access Detected",
                            "permission": g.get("Permission", "N/A"),
                        })
                if not public:
                    results.append({
                        "bucket": name,
                        "issue": "Private / Restricted",
                        "permission": "N/A",
                    })

            except ClientError as ce:
                results.append({
                    "bucket": name,
                    "issue": f"Access error: {ce.response['Error']['Code']}",
                    "permission": "N/A",
                })
            except Exception as e:
                results.append({
                    "bucket": name,
                    "issue": f"Unexpected error: {str(e)}",
                    "permission": "N/A",
                })

    except (NoCredentialsError, PartialCredentialsError):
        results.append({
            "bucket": None,
            "issue": "AWS credentials not found. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.",
            "permission": "N/A",
        })
    except Exception as e:
        results.append({
            "bucket": None,
            "issue": f"General error: {str(e)}",
            "permission": "N/A",
        })

    return results


if __name__ == "__main__":
    try:
        print("Script started...", file=sys.stderr)

        findings = analyze_s3_buckets()

        # Print JSON output for n8n (stdout)
        print(json.dumps(findings))

        print("Script completed successfully.", file=sys.stderr)
        sys.exit(0)

    except Exception as e:
        print("Script failed!", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.ex
