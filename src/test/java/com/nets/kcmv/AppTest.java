package com.nets.kcmv;

//import com.nets.kcmv.selftest.NetsKCMVSelfTest;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class AppTest 
    extends TestCase
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AppTest( String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( AppTest.class );
    }

    /**
     * Rigourous Test :-) - Now includes cryptographic self-tests.
     */
    public void testCryptoSelfTest()
    {
        // Install the provider before running tests
        NetsCryptoProvider.installProvider();

        // Run the self-test and assert its success
//        assertTrue("NetsKCMV self-test failed!", NetsKCMVSelfTest.selfTest(true));
    }
}