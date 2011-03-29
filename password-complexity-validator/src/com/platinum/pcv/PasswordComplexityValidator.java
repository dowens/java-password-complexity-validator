package com.platinum.pcv;

import com.platinum.dpv.DictionaryPasswordConfigException;
import com.platinum.dpv.DictionaryPasswordFileException;
import com.platinum.dpv.DictionaryPasswordValidator;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PasswordComplexityValidator validates the password meets your requirements
 * as far as complexity is concerned.
 *
 * License: Apache 2.0
 *
 * @author jlucier
 */
public class PasswordComplexityValidator {

    // For character determinations
    private static final int CHAR_LOWER_A = 'a';
    private static final int CHAR_LOWER_Z = 'z';
    private static final int CHAR_UPPER_A = 'A';
    private static final int CHAR_UPPER_Z = 'Z';
    private static final int CHAR_NUMERIC_ZERO = '0';
    private static final int CHAR_NUMERIC_NINE = '9';

    // Since the alpha and numeric checks handle the [a-zA-Z0-9] case in
    // earlier if statement checks, we can then assume the surrounding characters
    // within the range of the special char lower and upper values are in fact
    // special characters.  If it extends past the range, then it's no longer a symbol.
    private static final int CHAR_LOWER_SPECIAL_CHAR = ' ';
    private static final int CHAR_UPPER_SPECIAL_CHAR = '~';
    private static final int CHAR_EXTENDED_UPPER_SPECIAL_CHAR = 255;

    // Date regex and pattern
    private static final String REGEX_DATE_NUMERICAL = ".*([0-9]{1,4}[\\-.\\/]{1}"
            + "[0-9]{1,2}[\\-.\\/]{1}[0-9]{1,4}).*";
    private static final Pattern PATTERN_DATE_NUMERICAL = Pattern.compile(REGEX_DATE_NUMERICAL, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    // Phone regex and pattern
    private static final String REGEX_PHONE_NUMBER = ".*([0-9]{3}[\\-.]{1}"
            + "[0-9]{3}[\\-.]{1}[0-9]{4}).*";
    private static final Pattern PATTERN_PHONE_NUMBER = Pattern.compile(REGEX_PHONE_NUMBER, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
    
    // Configurable variables
    private static int minPasswordLength = 15;
    private static int maxPasswordLength = 50;
    private static int minLowerAlphaChars = 1;
    private static int minUpperAlphaChars = 1;
    private static int minSpecialChars = 1;
    private static int minNumericalChars = 1;
    private static boolean allowExtendedNonAsciiSymbols = false;
    private static int lastPasswordDifferInChars = 4;
    private static int passwordHistoryLen = 10;
    private static boolean restrictedByDictionary = true;
    private static boolean allowPhoneNumbers = false;
    private static boolean allowDates = false;

    /**
     * Override the default settings. This should be called on start up of the
     * app using the util.  This goes against normal conventions, but just go with it.
     * 
     * @param minPasswordLen
     * @param maxPasswordLen
     * @param minLowerAlphaChars
     * @param minUpperAlphaChars
     * @param minSpecialChars
     * @param minNumericalChars
     * @param lastPasswordDifferInChars
     * @param restricedByDictionary
     */
    public static synchronized void configure(int newMinPasswordLength, int newMaxPasswordLength,
            int newMinLowerAlphaChars, int newMinUpperAlphaChars, int newMinSpecialChars,
            int newMinNumericalChars, boolean newAllowExtendedNonAsciiSymbols,
            int newLastPasswordDifferInChars, int newPasswordHistoryLen,
            boolean newAllowPhoneNumbers, boolean newAllowDates, boolean newRestrictedByDictionary, float newDictionaryAccuracy,
            int newDictionaryMinWordLength) {

        minPasswordLength = newMinPasswordLength;
        maxPasswordLength = newMaxPasswordLength;
        minLowerAlphaChars = newMinLowerAlphaChars;
        minUpperAlphaChars = newMinUpperAlphaChars;
        minSpecialChars = newMinSpecialChars;
        minNumericalChars = newMinNumericalChars;
        allowExtendedNonAsciiSymbols = newAllowExtendedNonAsciiSymbols;
        lastPasswordDifferInChars = newLastPasswordDifferInChars;
        passwordHistoryLen = newPasswordHistoryLen;
        allowPhoneNumbers = newAllowPhoneNumbers;
        allowDates = newAllowDates;
        restrictedByDictionary = newRestrictedByDictionary;

        try {
            DictionaryPasswordValidator.configure(newDictionaryAccuracy, newDictionaryMinWordLength);
        } catch (DictionaryPasswordConfigException ex) {
            Logger.getLogger(PasswordComplexityValidator.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    /**
     * Validates if a password meets our requirements. Throws an exception with
     * a reason if it does not.
     *
     * @param newPassword
     * @param oldPasswordsNewestToOldest
     * @throws PasswordComplexityException
     */
    public static void validatePassword(String newPassword, ArrayList<String> oldPasswordsNewestToOldest) throws PasswordComplexityException {

        if (newPassword == null) {
            throw new PasswordComplexityException("You cannot have a null password.");
        }

        // Validate the password meets our character and length restrictions
        characterAndLengthValidations(newPassword);

        // Date validation
        dateValidation(newPassword);

        // Phone number validation
        phoneNumberValidation(newPassword);

        // Check the password doesn't contain dictionary words
        if (restrictedByDictionary == true) {
            try {
                DictionaryPasswordValidator dPV = DictionaryPasswordValidator.getInstance();
                if (dPV.isPasswordDictionaryBased(newPassword) == true) {
                    throw new PasswordComplexityException("Your password cannot contain dictionary words.");
                }
            } catch (DictionaryPasswordFileException ex) {

                Logger.getLogger(PasswordComplexityValidator.class.getName()).log(Level.SEVERE, null, ex);
                throw new PasswordComplexityException("Error attempting to load up the dictionary.", ex);
            }
        }


        // Validate it isn't a previous password, and the last password has changed
        // enough to meet our requirements.
        previousPasswordValidations(newPassword, oldPasswordsNewestToOldest);


        // Success, we've survived the battery of tests.
    }

    private static void dateValidation(String newPassword) throws PasswordComplexityException {

        if (allowDates == false) {
            Matcher m = PATTERN_DATE_NUMERICAL.matcher(newPassword);
            if (m.matches() == true) {
                throw new PasswordComplexityException("Your password cannot contain dates.");
            }
        }

    }

    private static void phoneNumberValidation(String newPassword) throws PasswordComplexityException {

        if (allowPhoneNumbers == false) {
            Matcher m = PATTERN_PHONE_NUMBER.matcher(newPassword);
            if (m.matches() == true) {
                throw new PasswordComplexityException("Your password cannot contain phone numbers.");

            }
        }

    }

    /**
     * This validates against your list of previous passwords. It does a
     * comparison against the last 10 characters to see if the passwords match
     * up. It also does a difference test to ensure the new password is X amount
     * of characters different then the last password.
     *
     * @param newPassword
     * @param oldPasswordsNewestToOldest
     * @throws PasswordComplexityException
     */
    private static void previousPasswordValidations(String newPassword, ArrayList<String> oldPasswordsNewestToOldest) throws PasswordComplexityException {

        if (oldPasswordsNewestToOldest != null) {

            int oldPasswordsCount = oldPasswordsNewestToOldest.size();
            if (oldPasswordsCount > 0) {

                // Validate we have 4 chars differing from the last password
                // Case Sensitive!
                String lastOldPassword = oldPasswordsNewestToOldest.get(0);
                try {
                    if (getLevenshteinDistance(newPassword, lastOldPassword) < lastPasswordDifferInChars) {
                        throw new PasswordComplexityException("The password must differ by at least " + lastPasswordDifferInChars + " characters.");
                    }
                } catch (IllegalArgumentException e) {
                    throw new PasswordComplexityException("Error doing Levenshtein Distance calculation.", e);
                }

                // Validate we haven't used this password in the last X changes
                // Case Sensitive!
                for (int r = 0; r < oldPasswordsCount && r < passwordHistoryLen; r++) {

                    if (oldPasswordsNewestToOldest.get(r).equals(newPassword)) {
                        throw new PasswordComplexityException("You may not use a password which has been used within the last " + passwordHistoryLen + " password changes.");
                    }
                }

            }
        }

    }

    /**
     * Check it meets the length and character requirements
     *
     * @param password
     * @throws PasswordComplexityException
     */
    private static void characterAndLengthValidations(String password) throws PasswordComplexityException {

        int passwordLen = password.length();

        if (passwordLen < minPasswordLength) {
            throw new PasswordComplexityException("The password must be at least " + minPasswordLength + " characters in length.");
        }

        if (passwordLen > maxPasswordLength) {
            throw new PasswordComplexityException("The password must be at less than " + maxPasswordLength + " characters in length.");
        }

        int alphaLowerCharsCount = 0;
        int alphaUpperCharsCount = 0;
        int numericCharsCount = 0;
        int specialCharsCount = 0;

        // Count the characters
        char passwordChar;
        Matcher specialCharMatcher;
        for (int i = 0; i < passwordLen; i++) {
            passwordChar = password.charAt(i);
            if (passwordChar >= CHAR_LOWER_A && passwordChar <= CHAR_LOWER_Z) {
                alphaLowerCharsCount++;
            } else if (passwordChar >= CHAR_UPPER_A && passwordChar <= CHAR_UPPER_Z) {
                alphaUpperCharsCount++;
            } else if (passwordChar >= CHAR_NUMERIC_ZERO && passwordChar <= CHAR_NUMERIC_NINE) {
                numericCharsCount++;
            } else if (allowExtendedNonAsciiSymbols == false &&
                    passwordChar >= CHAR_LOWER_SPECIAL_CHAR && passwordChar <= CHAR_UPPER_SPECIAL_CHAR) {
                specialCharsCount++;
            } else if (allowExtendedNonAsciiSymbols == true &&
                    passwordChar >= CHAR_LOWER_SPECIAL_CHAR && passwordChar <= CHAR_EXTENDED_UPPER_SPECIAL_CHAR) {
                specialCharsCount++;
            }  else {
                throw new PasswordComplexityException("Invalid password character entered.  You can use: a-z, A-Z, 0-9, Symbols");
            }
        }

        if (alphaLowerCharsCount < minLowerAlphaChars) {
            throw new PasswordComplexityException("The password must contain at least " + minLowerAlphaChars + " lowercase alpha (a-z) characters.");
        }

        if (alphaUpperCharsCount < minUpperAlphaChars) {
            throw new PasswordComplexityException("The password must contain at least " + minUpperAlphaChars + " uppercase alpha (A-Z) characters.");
        }

        if (numericCharsCount < minNumericalChars) {
            throw new PasswordComplexityException("The password must contain at least " + minNumericalChars + " numerical (0-9) characters.");
        }

        if (specialCharsCount < minSpecialChars) {
            throw new PasswordComplexityException("The password must contain at least " + minSpecialChars + " special (symbols such as: !@#) characters.");
        }
    }

    /**
     * The Levenshtein Distance formula. This is modified from the Apache
     * Commons version to support longer strings and to use a flat array.
     *
     * @param s
     * @param t
     * @return
     */
    private static int getLevenshteinDistance(String s, String t) {
        if (s == null || t == null) {
            throw new IllegalArgumentException("Strings must not be null");
        }

        int n = s.length(); // length of s
        int m = t.length(); // length of t

        if (n == 0) {
            return m;
        } else if (m == 0) {
            return n;
        }

        int p[] = new int[n + 1]; // 'previous' cost array, horizontally
        int d[] = new int[n + 1]; // cost array, horizontally
        int dSwap[]; // placeholder to assist in swapping p and d

        // indexes into strings s and t
        int i; // iterates through s
        int j; // iterates through t

        char tJ; // jth character of t

        int cost; // cost

        for (i = 0; i <= n; i++) {
            p[i] = i;
        }

        for (j = 1; j <= m; j++) {
            tJ = t.charAt(j - 1);
            d[0] = j;

            for (i = 1; i <= n; i++) {
                cost = s.charAt(i - 1) == tJ ? 0 : 1;
                // minimum of cell to the left+1, to the top+1, diagonally left
                // and up +cost
                d[i] = Math.min(Math.min(d[i - 1] + 1, p[i] + 1), p[i - 1] + cost);
            }

            // copy current distance counts to 'previous row' distance counts
            dSwap = p;
            p = d;
            d = dSwap;
        }

        // our last action in the above loop was to switch d and p, so p now
        // actually has the most recent cost counts
        return p[n];
    }
}
