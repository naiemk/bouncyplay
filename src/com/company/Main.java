package com.company;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class Main {
    public static PrivateKey keyToValue(byte[] pkcs8key) throws GeneralSecurityException {

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8key);
        KeyFactory factory = KeyFactory.getInstance("ECDSA");
        PrivateKey privateKey = factory.generatePrivate(spec);
        return privateKey;
    }

    public static X9ECParameters getCurve() {
        return SECNamedCurves.getByName("secp256r1");
    }

    public static BigInteger privateKey(SecureRandom random) {
        BigInteger d;
        BigInteger n = getCurve().getN();
        do
        {
            d = new BigInteger(n.bitLength(), random);
        }
        while (d.equals(ECConstants.ZERO)  || (d.compareTo(n) >= 0));
        return d;
    }

    public static ECPoint publicKeyFromPrivateKey(BigInteger privateKey, X9ECParameters curve) {
        return curve.getG().multiply(privateKey);
    }

    public static String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static void crypt() {
        try {
            SecureRandom random = new SecureRandom("HELLO".getBytes());

//            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");


            X9ECParameters curve = getCurve();
            ECDomainParameters domain = new ECDomainParameters (curve.getCurve (), curve.getG (), curve.getN (), curve.getH ());

            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters (domain, random);
            generator.init (keygenParams);
            AsymmetricCipherKeyPair keypair = generator.generateKeyPair ();
            ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate ();
            ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic ();

            //KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
            //g.initialize(ecSpec, new SecureRandom());
            //KeyPair pair = g.generateKeyPair();


            // Now use manual methods
            SecureRandom manRandom = new SecureRandom("HELLO".getBytes());
//            BigInteger manualPrivate = privateKey(manRandom);
            BigInteger manualPrivate = privParams.getD();
            ECPoint manualPublic = publicKeyFromPrivateKey(manualPrivate, curve);

            System.out.println(manualPrivate + "\nAND\n" + privParams.getD());
            System.out.println();
            System.out.println(b64(manualPublic.getEncoded()) + "\nAND\n" + b64(pubParams.getQ().getEncoded()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void distributedPublicKey() {
        X9ECParameters curve = getCurve();

        SecureRandom random = new SecureRandom("HELLO".getBytes());
        BigInteger p1 = privateKey(random);
        BigInteger p2 = privateKey(random);
        BigInteger p3 = privateKey(random);
        BigInteger p4 = privateKey(random);

        BigInteger p = p1.add(p2).add(p3).add(p4);
        System.out.println("Full public " + b64(publicKeyFromPrivateKey(p, curve).getEncoded()));

        ECPoint pub = publicKeyFromPrivateKey(p1, curve).add(
                publicKeyFromPrivateKey(p2, curve).add(
                        publicKeyFromPrivateKey(p3, curve).add(
                                publicKeyFromPrivateKey(p4, curve)
                        )
                )
        );

        System.out.println("n-d  public " + b64(pub.getEncoded()));
    }

    public static void main(String[] args) {
//        crypt();
        distributedPublicKey();
    }
}
