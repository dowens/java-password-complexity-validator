package com.platinum.pcv.test;

import com.platinum.pcv.PasswordComplexityException;
import com.platinum.pcv.PasswordComplexityValidator;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author jlucier
 */
public class PasswordComplexityTest {

    private static final String GENERIC_SUCCESS_PW = "AAAAbbbb1111@@@@";
    private static final String MIN_LENGTH_FAIL_PW = "a2b3c@!";
    private static final String CHAR_UPPER_FAIL_PW = "aaaabbbb1111@@@@";
    private static final String CHAR_LOWER_FAIL_PW = "AAAABBBB1111@@@@";
    private static final String CHAR_NUMERIC_FAIL_PW = "AAAAbbbbDDDD@@@@";
    private static final String CHAR_SYMBOL_FAIL_PW = "AAAAbbbb111122222";
    private static final String OLD_PW = "nnnnTTTT3333!&&&";
    private static final String PREV_FOUR_CHAR_PW = "ttttYYYY3333!&&&";
    private static final String FOUR_CHAR_FAIL_PW = "ttTTyYYY3333!&&&"; // 3 char diff
    private static final String FOUR_CHAR_SUCCESS_PW = "ttTTyyYY3333!&&&"; // 4 char diff
    private ArrayList<String> samplePreviousPasswords;

    public PasswordComplexityTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {

        samplePreviousPasswords = new ArrayList<String>(10);
        samplePreviousPasswords.add(PREV_FOUR_CHAR_PW);
        samplePreviousPasswords.add(OLD_PW);
        samplePreviousPasswords.add("Password3");
        samplePreviousPasswords.add("Password4");
        samplePreviousPasswords.add("Password5");
        samplePreviousPasswords.add("Password6");
        samplePreviousPasswords.add("Password7");
        samplePreviousPasswords.add("Password8");
        samplePreviousPasswords.add("Password9");
        samplePreviousPasswords.add("Password10");
    }

    @After
    public void tearDown() {
    }

    @Test
    public void nullPasswordTest() {
        try {
            PasswordComplexityValidator.validatePassword(null, samplePreviousPasswords);
        } catch (PasswordComplexityException ex) {
            assertTrue(ex.getMessage().toLowerCase().contains("cannot have a null password"));
            Logger.getLogger(PasswordComplexityTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void minLengthFailTest() {
        try {
            PasswordComplexityValidator.validatePassword(MIN_LENGTH_FAIL_PW, samplePreviousPasswords);
        } catch (PasswordComplexityException ex) {
            assertTrue(ex.getMessage().toLowerCase().contains("password must be at least"));
            Logger.getLogger(PasswordComplexityTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void charUpperFailTest() {
        try {
            PasswordComplexityValidator.validatePassword(CHAR_UPPER_FAIL_PW, samplePreviousPasswords);
        } catch (PasswordComplexityException ex) {
            assertTrue(ex.getMessage().toLowerCase().contains("uppercase alpha"));
            Logger.getLogger(PasswordComplexityTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void charLowerFailTest() {
        try {
            PasswordComplexityValidator.validatePassword(CHAR_LOWER_FAIL_PW, samplePreviousPasswords);
        } catch (PasswordComplexityException ex) {
            assertTrue(ex.getMessage().toLowerCase().contains("lowercase alpha"));
            Logger.getLogger(PasswordComplexityTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void charNumericFailTest() {
        try {
            PasswordComplexityValidator.validatePassword(CHAR_NUMERIC_FAIL_PW, samplePreviousPasswords);
        } catch (PasswordComplexityException ex) {
            assertTrue(ex.getMessage().toLowerCase().contains("numerical"));
            Logger.getLogger(PasswordComplexityTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void charSymbolFailTest() {
        try {
            PasswordComplexityValidator.validatePassword(CHAR_SYMBOL_FAIL_PW, samplePreviousPasswords);
        } catch (PasswordComplexityException ex) {
            assertTrue(ex.getMessage().toLowerCase().contains("special"));
            Logger.getLogger(PasswordComplexityTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void oldPasswordFailTest() {
        try {
            PasswordComplexityValidator.validatePassword(OLD_PW, samplePreviousPasswords);
        } catch (PasswordComplexityException ex) {
            assertTrue(ex.getMessage().toLowerCase().contains("may not use a password which has been used within"));
            Logger.getLogger(PasswordComplexityTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void lastFourCharsFailTest() {
        try {
            PasswordComplexityValidator.validatePassword(FOUR_CHAR_FAIL_PW, samplePreviousPasswords);
        } catch (PasswordComplexityException ex) {
            assertTrue(ex.getMessage().toLowerCase().contains("password must differ by at least"));
            Logger.getLogger(PasswordComplexityTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void lastFourCharsSuccessTest() {
        try {
            PasswordComplexityValidator.validatePassword(FOUR_CHAR_SUCCESS_PW, samplePreviousPasswords);
            assertTrue(true);
        } catch (PasswordComplexityException ex) {
            assertTrue(false);
            Logger.getLogger(PasswordComplexityTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void nullHistoryListTest() {

        // This should return success
        try {
            PasswordComplexityValidator.validatePassword(GENERIC_SUCCESS_PW, null);
            assertTrue(true);
        } catch (PasswordComplexityException ex) {
            assertTrue(false);
        }
    }

    @Test
    public void successTest() {

        // This should return success
        try {
            PasswordComplexityValidator.validatePassword(GENERIC_SUCCESS_PW, samplePreviousPasswords);
            assertTrue(true);
        } catch (PasswordComplexityException ex) {
            assertTrue(false);
        }
    }
}
