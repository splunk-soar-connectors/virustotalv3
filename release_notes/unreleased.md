**Unreleased**

* SDKifying the virus total app
* Previous versions of the app would pass every action run with the following error codes and messages {400: "NotAvailableYet", 404: "NotFoundError", 409: "AlreadyExistsError"}. This version of the app no longer silently passes these kinds of failures.  