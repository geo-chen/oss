# Unauthenticated Email Oracle via isSurveyResponsePresentAction

The `isSurveyResponsePresentAction` server action returns whether a specific email address has responded to a survey. It requires no authentication and has no rate limiting. Any unauthenticated actor who knows a public survey link can use it as a boolean oracle to determine which email addresses have responded to that survey.


## Fix
- https://github.com/formbricks/formbricks/pull/8094#event-26019092821

<img width="1162" height="304" alt="image" src="https://github.com/user-attachments/assets/f63c9d92-03df-4b31-b32c-abbe2ec03467" />
