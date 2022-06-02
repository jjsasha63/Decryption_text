import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

class Main{

    private static final String alphabet = new String("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz~!@#$%^&*()_+`1234567890-=<>?:\"{}|,./;'[]\\ ");
    private static final List<URL> files  = new ArrayList<URL>(){{
        try {
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000001_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000002_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000003_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000004_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000005_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000006_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000007_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000008_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000009_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000010_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000011_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000012_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000013_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000014_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000015_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000016_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000017_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000018_RSA.txt"));
            add(new URL("https://ecc.math.uni.lodz.pl/~frydrych/cryptography/e/Ex_0000019_RSA.txt"));
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }};


   private static List<Integer> prime_factors(int number){
        List<Integer> factors = new ArrayList<>();
        for(int i = 2; i <= number; i++) {
            while (number % i == 0) {
                factors.add(i);
                number = number / i;
            }
        }
        return factors;
    }

    private static int[] gcd(int exp, int phi) {
        if (phi == 0)
            return new int[] { exp, 1, 0 };

        int[] vals = gcd(phi, exp % phi);
        int d = vals[0];
        int a = vals[2];
        int b = vals[1] - (exp / phi) * vals[2];
        return new int[] { d, a, b ,phi};
    }

    private static int phi(List<Integer> factors){
       int phi = 1;
       for(int i:factors){
       phi = phi * (i-1);
       }
       return phi;
    }

    private static int priv_exp(int[] gcd){
       if (gcd[1]<0) return gcd[3] - Math.abs(gcd[1])%gcd[3];
       else return gcd[1]%gcd[3];
    }


    private static char get_char(int number){
       if (number<=98) return alphabet.charAt(number-2);
       else return ' ';
    }
    private static int decrypt(int base, int exp, int modu){
       int fin;
        if (exp == 0) return 1;
        if (exp == 1) return base % modu;
        int t = decrypt(base, exp / 2,modu);
        t = (t * t) % modu;
        if (exp % 2 == 0)
            return t;
        else
            return ((base % modu) * t) % modu;
    }

    private static List<Integer> parse_key(URL url) throws IOException {
       boolean switch_ = false;
       List<Integer> key = new ArrayList<>();
       String line;
        BufferedReader read = new BufferedReader( new InputStreamReader(url.openStream()));
        while((line = read.readLine())!= null){
            if(line.contains("*******************************************")){
                switch_ = true;
                continue;
            }
            if(switch_){
                line = line.replaceAll("[^\\d]", " ");
                line = line.trim();
                line = line.replaceAll(" +", " ");
                String[] array = line.split(" ");
                for(String i:array) key.add(Integer.parseInt(i));
                break;
                }
        }
        read.close();
        return key;
    }

    private static List<Integer> parse_data(URL url) throws IOException {
        boolean switch_ = false;
        List<Integer> data = new ArrayList<>();
        String line;
        int k=-2;
        BufferedReader read = new BufferedReader( new InputStreamReader(url.openStream()));
        while((line = read.readLine())!= null){
            if(line.contains("*******************************************")){
                if(k==-2) {
                    switch_ = true;
                    continue;
                } else if(k>0)break;
            }
            if(k>=0&&switch_){
                line = line.replaceAll("[^\\d]", " ");
                line = line.trim();
                line = line.replaceAll(" +", " ");
                if(line.isEmpty()) break;
                String[] array = line.split(" ");
                for(String i:array) data.add(Integer.parseInt(i));
            }
            if(switch_) k++;

        }
        read.close();
        return data;
    }


    //mode - 0 decrypt all the files, 1-19 - decrypt specific file

    public static void dec(int mode) throws IOException {
       //List<String> output = new ArrayList<>();
       if(mode==0){
       for(URL file: files){
           List<Integer> key = parse_key(file);
           List<Integer> data = parse_data(file);
           int priv_exp = priv_exp(gcd(key.get(1),phi(prime_factors(key.get(0)))));
           String temp = new String();
           for(int i: data) {
               char a = get_char(decrypt(i,priv_exp,key.get(0)));
               temp += a;
               if(a==','||a==':'||a=='.'||a==';') temp += "\n";
           }
          // output.add(temp); if we need to store it somewhere
           System.out.println(temp);
      }
       }else{
           List<Integer> key = parse_key(files.get(mode - 1));
           List<Integer> data = parse_data(files.get(mode - 1));
           int priv_exp = priv_exp(gcd(key.get(1),phi(prime_factors(key.get(0)))));
           String temp = new String();
           for(int i: data) {
               char a = get_char(decrypt(i,priv_exp,key.get(0)));
               temp += a;
               if(a==','||a==':'||a=='.'||a==';'||a=='!') temp += "\n";
           }
           // output.add(temp); if we need to store it somewhere
           System.out.println(temp);
       }

    }



    public static void main(String[] args) throws IOException {

        dec(0);
    }
}