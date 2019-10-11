package bouncycas.bouncycas;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;

import org.junit.*;

public class ValuesTests {
	
	@Test
	public void testCases() throws GeneralSecurityException {
		
	 Setup.installProvider();
	 
	 SecretKey secKey = Main.generateKey();
     Arrays.areEqual(ExValues.SampleInput, Main.ecbDecrypt(secKey, Main.ecbEncrypt(secKey, ExValues.SampleInput)));

     byte[][] cbcOutput = Main.cbcEncrypt(secKey, ExValues.SampleInput);
     Arrays.areEqual(ExValues.SampleInput, Main.cbcDecrypt(secKey, cbcOutput[0], cbcOutput[1]));

     byte[][] cfbOutput = Main.cfbEncrypt(secKey, ExValues.SampleInput);
     Arrays.areEqual(ExValues.SampleInput, Main.cfbDecrypt(secKey, cfbOutput[0], cfbOutput[1]));

     byte[][] ctrOutput = Main.ctrEncrypt(secKey, ExValues.SampleInput);
     Arrays.areEqual(ExValues.SampleInput, Main.ctrDecrypt(secKey, ctrOutput[0], ctrOutput[1]));

     Object[] gcmOutput = Main.gcmEncrypt(secKey, ExValues.SampleInput);
     Arrays.areEqual(ExValues.SampleInput, Main.gcmDecrypt(secKey, (AlgorithmParameters)gcmOutput[0], (byte[])gcmOutput[1]));

     Object[] ccmOutput = Main.ccmEncrypt(secKey, ExValues.SampleInput);
     Arrays.areEqual(ExValues.SampleInput, Main.ccmDecrypt(secKey, (AlgorithmParameters)ccmOutput[0], (byte[])ccmOutput[1]));

     Object[] aeadOutput = Main.aeadEncrypt(secKey, ExValues.SampleInput, ExValues.SampleTwoBlockInput);
     Arrays.areEqual(ExValues.SampleInput, Main.aeadDecrypt(secKey, (AlgorithmParameters)aeadOutput[0], (byte[])aeadOutput[1], ExValues.SampleTwoBlockInput));

     byte[][] ctsOutput = Main.ctsEncrypt(secKey, ExValues.SampleTwoBlockInput);
     Arrays.areEqual(ExValues.SampleTwoBlockInput, Main.ctsDecrypt(secKey, ctsOutput[0], ctsOutput[1]));

     Arrays.areEqual(ExValues.SampleInput, Main.ecbDecrypt(secKey, Main.ecbEncrypt(secKey, ExValues.SampleInput)));
     Arrays.areEqual(ExValues.SampleInput, Main.ecbDecrypt(secKey, Main.ecbEncrypt(secKey, ExValues.SampleInput)));
     
     Arrays.areEqual(ExValues.SampleAesKey.getEncoded(), Main.unwrapKey(secKey, Main.wrapKey(secKey, ExValues.SampleAesKey)).getEncoded());
     Arrays.areEqual(ExValues.SampleHMacKey.getEncoded(), Main.unwrapKeyWithPadding(secKey, Main.wrapKeyWithPadding(secKey, ExValues.SampleHMacKey)).getEncoded());
   }
}
