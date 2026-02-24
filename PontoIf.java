import java.security.MessageDigest;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class PontoIf {

    static Scanner sc = new Scanner(System.in);

    static class AESUtil {
        private static final String chave = "1234567890123456";

        public static String criptografar(String texto) throws Exception {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec key = new SecretKeySpec(chave.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return Base64.getEncoder().encodeToString(cipher.doFinal(texto.getBytes()));
        }

        public static String descriptografar(String texto) throws Exception {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec key = new SecretKeySpec(chave.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(Base64.getDecoder().decode(texto)));
        }
    }

    static class HashUtil {
        public static String sha256(String texto) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(texto.getBytes());
                StringBuilder sb = new StringBuilder();
                for (byte b : hash) {
                    sb.append(String.format("%02x", b));
                }
                return sb.toString();
            } catch (Exception e) {
                return null;
            }
        }
    }

    static class Professor {

        boolean presente;
        
        String cripUser;
        String userIDCripto;
        String senhaHash;
        boolean logado;
        void criarConta() throws Exception {
            System.out.println("Digite seu nome:");
            String user = sc.nextLine();

            System.out.println("Digite seu ID:");
            String userID = sc.nextLine();

            System.out.println("Crie uma senha:");
            String senha = sc.nextLine();

            presente = false;

            senhaHash = HashUtil.sha256(senha);
            cripUser = AESUtil.criptografar(user);
            userIDCripto = AESUtil.criptografar(userID);

            System.out.println(cripUser);
            System.out.println(userIDCripto);
            System.out.println(senhaHash);
        }

        void entrar() throws Exception {
            System.out.println("Digite seu usuário:");
            String usuario = sc.nextLine();

            System.out.println("Digite sua senha:");
            String senha = sc.nextLine();

            System.out.println("Digite seu ID:");
            String id = sc.nextLine();

            String usuarioCripto = AESUtil.criptografar(usuario);
            String hashSenha = HashUtil.sha256(senha);
            String criptoID = AESUtil.criptografar(id);

            if (usuarioCripto.equals(cripUser) &&
                hashSenha.equals(senhaHash) &&
                criptoID.equals(userIDCripto)) {

                System.out.println("Login feito com sucesso");
                String user = AESUtil.descriptografar(cripUser);
                System.out.println("Olá " + user);
                logado=true;

            } else {
                System.out.println("Credenciais incorretas");
            }
        }

        void baterPontoEntrada() throws Exception {if (!logado) {
        System.out.println("Você precisa estar logado para bater o ponto!");
        return;
    }
            String user = AESUtil.descriptografar(cripUser);
            presente = true;
            System.out.println("Olá " + user + ", seu ponto foi batido");
        }
        void baterPontoSaida() throws Exception{
            
            if (!logado) {
        System.out.println("Você precisa estar logado para bater o ponto!");
        return;
    }
            String user = AESUtil.descriptografar(cripUser);
            presente = true;
            System.out.println("Até mais " + user + ", seu ponto foi batido");
        }
    }

    public static void main(String[] args) throws Exception {
        Professor prof = new Professor();
        prof.criarConta();
        prof.entrar();
        prof.baterPontoEntrada();
        prof.baterPontoSaida();
    }
}