package aplicaciones.sainz.jorge.ejemploaescrypt;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import utilidades.AdvancedCrypto;
import utilidades.PasswordGenerator;

import static utilidades.EncryptUserName.encodeAccount;
import static utilidades.EncryptUserName.validAccount;
import static utilidades.PasswordGenerator.getPassword;

public class AESCryptMain extends Activity {

    String crypto = null;
    String pass = "f5R$y5R%";
    String src = "ABCDEFGHIJKabcdefghijk123456789!@#$%^&*(";

    private AdvancedCrypto ac;
    private Button encriptar;
    private Button desencriptar;
    private Button genPass;
    private Button account;
    private TextView resultado;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_aescrypt_main);

        encriptar = (Button) findViewById(R.id.encriptar);
        desencriptar = (Button) findViewById(R.id.desencriptar);
        account = (Button) findViewById(R.id.account);
        genPass = (Button) findViewById(R.id.genPass);

        resultado = (TextView) findViewById(R.id.resultado);

        ac = AdvancedCrypto.getInstance();

        encriptar.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                try {

                    crypto = ac.encrypt(ac.getSecretKey(pass, ac.generateSalt(pass)), src);

                    resultado.setText(crypto);
                    Log.i("ENC", crypto);
                } catch (Exception e) {
                    e.printStackTrace();
                    resultado.setText(e.toString());
                }
            }
        });

        desencriptar.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                try {
                    String clearText = ac.decrypt(ac.getSecretKey(pass, ac.generateSalt(pass)), crypto);

                    resultado.setText(clearText);
                } catch (Exception e) {
                    e.printStackTrace();
                    resultado.setText(e.toString());
                }
            }
        });

        genPass.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 15; i++) {
                    try {
                        sb.append(getPassword(16)).append("\n");
                    } catch (PasswordGenerator.ExcepcionLongitud excepcionLongitud) {
                        sb.append(excepcionLongitud.getMessage()).append("\n");
                    }
                }
                resultado.setText(sb.toString());
            }
        });

        account.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                StringBuilder sb = new StringBuilder();

                String user = "pepe";
                String pass = "pepe123";

                String passcode = encodeAccount(user, pass);

                Log.i("PASSCODE", passcode);

                resultado.setText(passcode + "  " + validAccount("871cabcb453582a828ffc4233e6b1a78", user, pass));
            }
        });

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_aescrypt_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
