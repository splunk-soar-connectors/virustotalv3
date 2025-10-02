**Unreleased**

* SDKifying the virus total app
* Previous versions of the app would pass everyone action run for the following error codes and messages {400: "NotAvailableYet", 404: "NotFoundError", 409: "AlreadyExistsError"}. This version of the app no longer silently passes these kind of failures. 