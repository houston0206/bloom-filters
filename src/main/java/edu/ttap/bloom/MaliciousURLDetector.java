package edu.ttap.bloom;

import java.io.FileNotFoundException;
import java.io.File;
import java.util.List;
import java.util.Scanner;
import java.util.function.Function;
import java.util.concurrent.ThreadLocalRandom;
import com.google.common.hash.Hashing;
import java.nio.charset.Charset;

/**
 * A simple malicious URL detector program that utilizes a Bloom Filter and a
 * dataset of known malicious URLs to efficiently check whether a URL is
 * potentially malicious.
 */
public class MaliciousURLDetector {
    // From: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
    public static final String DATA_PATH = "data/malicious_phish.csv";

    /**
     * Creates a list of <code>num</code> string hash functions utilizing the
     * Murmur3 hashing algorithm.
     * @param num the number of hash functions
     * @return a list of <code>num</code> string hash functions
     */
    public static List<Function<String, Integer>> makeStringHashFunctions(int num) {
        return java.util.stream.IntStream.range(0, num).
            mapToObj(i -> {
                int seed = ThreadLocalRandom.current().nextInt();
                return (Function<String, Integer>) str -> 
                    Hashing.murmur3_128(seed).hashString(str, Charset.defaultCharset()).asInt();
            }).
            collect(java.util.stream.Collectors.toList());
    }

    /**
     * @param numBits the number of bits dedicated to the filter
     * @param numHashFunctions the number of hash functions to use
     * @return a Bloom filter for detecting malicious URLs.
     */
    public static BloomFilter<String> makeURLFilter(
            int numBits, int numHashFunctions) throws FileNotFoundException {
        System.err.println("Check 3.1");
        Scanner scan = new Scanner(new File(DATA_PATH));
        System.err.println("Check 3.2");
        BloomFilter<String> filter = new BloomFilter<>(numBits, 
            makeStringHashFunctions(numHashFunctions));
        System.err.println("Check 3.3");
        while (scan.hasNextLine()) {
            String[] line = scan.nextLine().split(",");
            if (line.length < 2) {
                System.err.println("Malformed line: " + String.join(",", line));
                System.exit(1);
            }
            if (!(line[1].equals("benign"))) {
                filter.add(line[0]);
            }
        }
        System.err.println("Check 3.4");
        scan.close();
        return filter;
    }

    /**
     * The main method for the program.
     * @param args the arguments to the program
     * @throws FileNotFoundException
     */
    public static void main(String[] args) throws FileNotFoundException {
        if (args.length != 2) {
            System.err.println("Usage: java MaliciousURLDetector <numBits> <numHashFunctions>");
            return;
        }
        System.err.println("Check 1");
        int numBits = Integer.parseInt(args[0]);
        System.err.println("Check 2");
        int numHashFunctions = Integer.parseInt(args[1]);
        System.err.println("Check 3");
        BloomFilter<String> filter = makeURLFilter(numBits, numHashFunctions);
        System.err.println("Check 4");

        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("Enter URL (or 'exit' to quit): ");
            String url = scanner.nextLine();

            if (url.equals("exit")) {
                break;
            }

            if (filter.contains(url)) {
                System.out.println("URL is potentially malicious.");
            } else {
                System.out.println("URL appears to be benign.");
            }
        }
        scanner.close();
    }
}