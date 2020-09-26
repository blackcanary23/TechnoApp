package com.example.technoapp;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import java.io.IOException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


public class MainActivity extends AppCompatActivity {

    private ArrayList<String> certificateChain = new ArrayList<>();
    private Certificate[] certificates = new Certificate[0];
    private X509Certificate intermediate = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        getRootCertificate();
    }

    private void getRootCertificate() {

        new Thread(new Runnable() {
            @Override
            public void run() {

                certificateChain.clear();


                URL url;
                HttpsURLConnection connection = null;

                try {

                    url = new URL("https://github.com/blackcanary23?tab=repositories");

                    //url = new URL("https://site2.ru/cgi/users");

                    connection = (HttpsURLConnection) url.openConnection();
                    connection.connect();

                    certificates = connection.getServerCertificates();
                    //System.out.println(certificates.length + "LENGTH" + certificates[0] + certificates[1]);
                    intermediate = (X509Certificate) certificates[certificates.length - 1];
                } catch (IOException e) {

                    e.printStackTrace();
                } finally {

                    if (connection != null)
                        connection.disconnect();
                }

                TrustManagerFactory tmFactory = null;
                X509TrustManager x509Tm;

                try {

                    tmFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmFactory.init((KeyStore) null);
                } catch (NoSuchAlgorithmException | KeyStoreException e) {

                    e.printStackTrace();
                }


                assert tmFactory != null;
                TrustManager[] trustManagers = tmFactory.getTrustManagers();
                x509Tm = (X509TrustManager) trustManagers[0];
                X509Certificate[] issuers = x509Tm.getAcceptedIssuers();

                //
                validateCertificateChain();
                //

                if (certificateChain.size() != 0)
                {
                    for (X509Certificate issuer : issuers) {

                        try {

                            assert intermediate != null;
                            intermediate.verify(issuer.getPublicKey());
                            //System.out.println(issuer.getSubjectX500Principal().getName() + "ISSUER");
                            certificateChain.add(issuer.getSubjectX500Principal().getName());
                            System.out.println(certificateChain.size() + "SIZE");
                            break;
                        }
                        catch (CertificateException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {

                            e.printStackTrace();
                        }
                    }
                }

                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {

                    }
                });
            }
        }).start();
    }

    private void validateCertificateChain() {

        for (int i = 0; i < certificates.length; i++) {

            try {

                assert intermediate != null;
                certificates[i].verify(certificates[i + 1].getPublicKey());
                //certificateChain.add(certificates[i]);
                //certificateChain.add(certificates[i++]);
                //System.out.println("Hello" + ((X509Certificate) certificates[i]).getSubjectX500Principal().getName() + " " + ((X509Certificate) certificates[i + 1]).getSubjectX500Principal().getName());
                certificateChain.add(((X509Certificate) certificates[i]).getSubjectX500Principal().getName());
                certificateChain.add(((X509Certificate) certificates[i + 1]).getSubjectX500Principal().getName());
                break;
            }
            catch (CertificateException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {

                e.printStackTrace();
            }
        }
    }

    private void parsePrincipal() {

        ArrayList<String> cnList = new ArrayList<>();
        String regex = "(?:^|,\\s?)(?:CN=(?<val>\"(?:[^\"]|\"\")+\"|[^,]+))"; //

        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher("CN=github.com,O=GitHub\\, Inc.,L=San Francisco,ST=California,C=US CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US");

        while(m.find()) {

            String cn = m.group(1);
            cnList.add(cn);
            //System.out.println(cn + "REGEX");
        }
    }
}
