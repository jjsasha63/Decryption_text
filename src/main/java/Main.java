import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

class Main{

    // Creating a string of all the characters that can be used in the decryption.
    private static final String alphabet = new String("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz~!@#$%^&*()_+`1234567890-=<>?:\"{}|,./;'[]\\ ");
    // Creating a list of URLs.
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


   /**
    * > We keep dividing the number by the smallest possible prime factor until it is no longer divisible by that factor
    *
    * @param number The number to find the prime factors of.
    * @return A list of prime factors of the number.
    */
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

    /**
     * The function takes in two numbers, and returns an array of four numbers, where the first number is the greatest
     * common divisor of the two numbers, and the second and third numbers are the coefficients of the linear combination
     * of the two numbers that equals the greatest common divisor
     *
     * Extended Euclidean algorithm
     *
     * @param exp the exponent of the public key
     * @param phi the totient of the modulus
     * @return The GCD of the two numbers, the inverse of the first number, the inverse of the second number, and the phi
     * of the first number.
     */
    private static int[] gcd(int exp, int phi) {
        if (phi == 0)
            return new int[] { exp, 1, 0 };

        int[] vals = gcd(phi, exp % phi);
        int d = vals[0];
        int a = vals[2];
        int b = vals[1] - (exp / phi) * vals[2];
        return new int[] { d, a, b ,phi};
    }

    /**
     * > The function takes a list of factors and returns the totient of the product of the factors
     *
     * @param factors A list of prime factors of n
     * @return The totient of the number.
     */
    private static int phi(List<Integer> factors){
       int phi = 1;
       for(int i:factors){
       phi = phi * (i-1);
       }
       return phi;
    }

    /**
     * > It returns the modular inverse of the first number in the array, modulo the third number in the array
     * Fitting the return of gcd under specific rules of encription
     *
     * @param gcd an array of integers that contains the following:
     * @return The private exponent.
     */
    private static int priv_exp(int[] gcd){
       if (gcd[1]<0) return gcd[3] - Math.abs(gcd[1])%gcd[3];
       else return gcd[1]%gcd[3];
    }


    /**
     * It takes a number and returns a character by mapping this number to the alphabet
     *
     * @param number the number of the character you want to get
     * @return The character at the index of the number minus 2.
     */
    private static char get_char(int number){
       if (number<=98) return alphabet.charAt(number-2);
       else return ' ';
    }
    /**
     * If the exponent is even, square the base and divide the exponent by 2. If the exponent is odd, multiply the base by
     * the result of the function call with the exponent divided by 2.
     *
     * Decryption of the separate code
     *
     * @param base the base number
     * @param exp exponent
     * @param modu the modulus
     * @return The decrypted message presented as a number.
     */
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

    /**
     * It reads the URL, finds the line that contains the string "*******************************************", and then
     * reads the next line, which contains the key
     *
     * Get keys from the file
     *
     * @param url The URL of the file containing the key.
     * @return A list of integers
     */
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

    /**
     * It reads the data from the URL and returns a list of integers
     *
     * Get the data from the file
     *
     * @param url The url of the website to be parsed.
     * @return a list of integers.
     */
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


    /**
     * It decrypts the data in the file and prints it out
     *
     * @param mode 0 for all files, 1 for first file, 2 for second file, etc.
     */
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
               if(a==','||a==':'||a=='.'||a==';'||a=='!'||a=='?') temp += "\n";
           }
           //temp = temp.replaceAll("\n","");
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
               if(a==','||a==':'||a=='.'||a==';'||a=='!'||a=='?') temp += "\n";
           }
           //temp = temp.replaceAll("\n","");
           // output.add(temp); if we need to store it somewhere
           System.out.println(temp);
       }

    }



    public static void main(String[] args) throws IOException {

        dec(0);
    }
}