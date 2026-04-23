```markdown
# srdnlen — Log Path Traversal / Misconfiguration Chain (Writeup)

Solved.

## Flag

`srdnlen{d0uble_m1sC0nf_aR3_n0t_fUn}`

## Summary

This challenge was solved by chaining two misconfigurations:

1. A verbose server error (HTTP 500) leaked internal filesystem information via a Tomcat/JSP stack trace.
2. A path traversal in `receipt.jsp` allowed reading files outside the intended receipts directory, including Tomcat logs.

The Tomcat deployment logs revealed the deployed webapp directory name, which contained the flag.

## What Worked (site-only)

### 1) Trigger a 500 to leak a JSP source path

Send a `POST` request to:

- `POST /api/checkout.jsp`

with a **very long** `sid` value to trigger an HTTP 500.

Result:
- The error stack trace exposed a JSP source path in the server filesystem.
- This helped infer where the application was reading receipt files from.

### 2) Locate where receipts are read from

From the leaked information:

- Receipts are read from:  
  `/usr/local/tomcat/logs/receipts/`

This indicated receipt retrieval was likely implemented as a filesystem read based on user input.

### 3) Use path traversal in `receipt.jsp`

`receipt.jsp` takes an `id` parameter which is used to build a path relative to the receipts directory.

By using `..` traversal, read Tomcat Catalina logs:

- Example payload:  
  `id=../catalina.2026-02-28.log`

This works because the base is:

- `/usr/local/tomcat/logs/receipts/`

So the traversal escapes to:

- `/usr/local/tomcat/logs/catalina.2026-02-28.log`

### 4) Extract the flag from Tomcat startup logs

Inside `catalina.2026-02-28.log`, the startup/deploy lines show:

```

Deploying web application directory [/usr/local/tomcat/webapps/srdnlen{d0uble_m1sC0nf_aR3_n0t_fUn}]

```

The deployed web application directory name contains the flag directly.

## Root Cause / Vulnerability Chain

- **Verbose error handling** exposed internal paths via stack traces.
- **Path traversal** in `receipt.jsp` allowed reading arbitrary files relative to the receipts directory.
- **Sensitive logs** revealed deployment details, including the flag embedded in the webapp directory name.

## Notes

- No external tooling or out-of-band techniques were needed.
- This was effectively a **log disclosure via traversal**, enabled by an **information leak** from a 500 error.
```
