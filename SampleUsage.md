# Usage #

Firstly, configure the parameters.  This should be done on your applications start up, since you can't reinitialize the dictionary.

```

int minPasswordLength = 4;			// Minimum length of a password
int maxPasswordLength = 25;		// Maximum length of a password
int minLowerAlphaChars = 1;			// Minimum amount of lowercase alpha characters in the password
int minUpperAlphaChars = 1;			// Minimum amount of uppercase alpha characters in the password
int minSpecialChars = 1;			// Minimum amount of special characters in the password
int minNumericalChars = 1;			// Minimum amount of numerical characters in the password
boolean allowExtendedAsciiSymbols = false;  	// Allow extended ascii characters in the password?
int lastPasswordDifferInChars = 4;		// The password must differ by X amount of characters compared to the last one
int passwordHistoryLen = 4;  		// Validate we haven't used this password in this many iterations (we use the list of old pw's you pass in for this)
boolean allowPhoneNumbers = false;  	// Allow phone numbers in the password?
boolean allowDates = false; 			// Allow dates in the password?
boolean restrictedByDictionary = false;	// Deny dictionary words within the password?
float dictionaryAccuracy = 17;	// Default Bloom Filter settings
int dictionaryMinWordLength = 4; 	// Default dictionary word length.  Anything smaller and you'll get lots of hits
		    
PasswordComplexityValidator.configure(minPasswordLength, maxPasswordLength, minLowerAlphaChars, minUpperAlphaChars, minSpecialChars, 
		minNumericalChars, allowExtendedAsciiSymbols, lastPasswordDifferInChars, passwordHistoryLen, allowPhoneNumbers, allowDates, 
		restrictedByDictionary, dictionaryAccuracy, dictionaryMinWordLength);
```


Then to validate, you just need to pass in the password to validate against, as well as the list of previous passwords (in order of newest to oldest).  You can also pass in null if you have none, or an empty list.

```
        try {
	    ArrayList<PasswordHist> passHistList = [List of old passwords in newest to oldest order];
	    PasswordComplexityValidator.validatePassword(newPassword, passHistList );
	} catch (PasswordComplexityException ex) {
            // This will output the issue with the password to the console
	    System.out.println(ex.getMessage());
	}
```