package bouncycas.bouncycas;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ValuesTests {

	private SecretKey secKey;

	@Before
	public void setUp() {
		Setup.installProvider();
		try {
			secKey = Main.generateKey();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testEcbEncryptDecrypt() {
		try {
			Assert.assertArrayEquals(ExValues.SampleInput,
					Main.ecbDecrypt(secKey, Main.ecbEncrypt(secKey, ExValues.SampleInput)));
			Assert.assertArrayEquals(ExValues.SampleAesKey.getEncoded(),
					Main.unwrapKey(secKey, Main.wrapKey(secKey, ExValues.SampleAesKey)).getEncoded());
			Assert.assertArrayEquals(ExValues.SampleHMacKey.getEncoded(),
					Main.unwrapKeyWithPadding(secKey, Main.wrapKeyWithPadding(secKey, ExValues.SampleHMacKey))
							.getEncoded());
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Test
	public void testCfbEncryptDecrypt() {
		byte[][] cfbOutput;
		try {
			cfbOutput = Main.cfbEncrypt(secKey, ExValues.SampleInput);
			Assert.assertArrayEquals(ExValues.SampleInput, Main.cfbDecrypt(secKey, cfbOutput[0], cfbOutput[1]));
			Assert.assertArrayEquals(ExValues.SampleAesKey.getEncoded(),
					Main.unwrapKey(secKey, Main.wrapKey(secKey, ExValues.SampleAesKey)).getEncoded());
			Assert.assertArrayEquals(ExValues.SampleHMacKey.getEncoded(),
					Main.unwrapKeyWithPadding(secKey, Main.wrapKeyWithPadding(secKey, ExValues.SampleHMacKey))
							.getEncoded());
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testCtrEncryptDecrypt() {
		byte[][] ctrOutput;
		try {
			ctrOutput = Main.ctrEncrypt(secKey, ExValues.SampleInput);
			Assert.assertArrayEquals(ExValues.SampleInput, Main.ctrDecrypt(secKey, ctrOutput[0], ctrOutput[1]));
			Assert.assertArrayEquals(ExValues.SampleAesKey.getEncoded(),
					Main.unwrapKey(secKey, Main.wrapKey(secKey, ExValues.SampleAesKey)).getEncoded());
			Assert.assertArrayEquals(ExValues.SampleHMacKey.getEncoded(),
					Main.unwrapKeyWithPadding(secKey, Main.wrapKeyWithPadding(secKey, ExValues.SampleHMacKey))
							.getEncoded());
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testGcmEncryptDecrypt() {
		Object[] gcmOutput;
		try {
			gcmOutput = Main.gcmEncrypt(secKey, ExValues.SampleInput);
			Assert.assertArrayEquals(ExValues.SampleInput,
					Main.gcmDecrypt(secKey, (AlgorithmParameters) gcmOutput[0], (byte[]) gcmOutput[1]));
			Assert.assertArrayEquals(ExValues.SampleAesKey.getEncoded(),
					Main.unwrapKey(secKey, Main.wrapKey(secKey, ExValues.SampleAesKey)).getEncoded());
			Assert.assertArrayEquals(ExValues.SampleHMacKey.getEncoded(),
					Main.unwrapKeyWithPadding(secKey, Main.wrapKeyWithPadding(secKey, ExValues.SampleHMacKey))
							.getEncoded());
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testCbcEncryptDecrypt() {
		byte[][] cbcOutput;
		try {
			cbcOutput = Main.cbcEncrypt(secKey, ExValues.SampleInput);
			Assert.assertArrayEquals(ExValues.SampleInput, Main.cbcDecrypt(secKey, cbcOutput[0], cbcOutput[1]));
			Assert.assertArrayEquals(ExValues.SampleAesKey.getEncoded(),
					Main.unwrapKey(secKey, Main.wrapKey(secKey, ExValues.SampleAesKey)).getEncoded());
			Assert.assertArrayEquals(ExValues.SampleHMacKey.getEncoded(),
					Main.unwrapKeyWithPadding(secKey, Main.wrapKeyWithPadding(secKey, ExValues.SampleHMacKey))
							.getEncoded());
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testCcmEncryptDecrypt() {
		Object[] ccmOutput;
		try {
			ccmOutput = Main.ccmEncrypt(secKey, ExValues.SampleInput);
			Assert.assertArrayEquals(ExValues.SampleInput,
					Main.ccmDecrypt(secKey, (AlgorithmParameters) ccmOutput[0], (byte[]) ccmOutput[1]));
			Assert.assertArrayEquals(ExValues.SampleAesKey.getEncoded(),
					Main.unwrapKey(secKey, Main.wrapKey(secKey, ExValues.SampleAesKey)).getEncoded());
			Assert.assertArrayEquals(ExValues.SampleHMacKey.getEncoded(),
					Main.unwrapKeyWithPadding(secKey, Main.wrapKeyWithPadding(secKey, ExValues.SampleHMacKey))
							.getEncoded());
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testAeadEncryptDecrypt() {
		Object[] aeadOutput;
		try {
			aeadOutput = Main.aeadEncrypt(secKey, ExValues.SampleInput, ExValues.SampleTwoBlockInput);
			Assert.assertArrayEquals(ExValues.SampleInput, Main.aeadDecrypt(secKey, (AlgorithmParameters) aeadOutput[0],
					(byte[]) aeadOutput[1], ExValues.SampleTwoBlockInput));
			Assert.assertArrayEquals(ExValues.SampleAesKey.getEncoded(),
					Main.unwrapKey(secKey, Main.wrapKey(secKey, ExValues.SampleAesKey)).getEncoded());
			Assert.assertArrayEquals(ExValues.SampleHMacKey.getEncoded(),
					Main.unwrapKeyWithPadding(secKey, Main.wrapKeyWithPadding(secKey, ExValues.SampleHMacKey))
							.getEncoded());
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testCtsEncryptDecrypt() {
		byte[][] ctsOutput;
		try {
			ctsOutput = Main.ctsEncrypt(secKey, ExValues.SampleTwoBlockInput);
			Assert.assertArrayEquals(ExValues.SampleTwoBlockInput, Main.ctsDecrypt(secKey, ctsOutput[0], ctsOutput[1]));
			Assert.assertArrayEquals(ExValues.SampleAesKey.getEncoded(),
					Main.unwrapKey(secKey, Main.wrapKey(secKey, ExValues.SampleAesKey)).getEncoded());
			Assert.assertArrayEquals(ExValues.SampleHMacKey.getEncoded(),
					Main.unwrapKeyWithPadding(secKey, Main.wrapKeyWithPadding(secKey, ExValues.SampleHMacKey))
							.getEncoded());
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	}
}