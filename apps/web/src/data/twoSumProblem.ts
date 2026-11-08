import type { ProblemDefinition, SupportedLanguage } from "../types/problem";

export const twoSumProblem: ProblemDefinition = {
  id: "SH-ARR-001",
  title: "Two Sum",
  difficulty: "Easy",
  category: "Arrays & Hashing",
  tags: ["Array", "Hash Map"],
  summary: "Find two distinct indices whose values add up to the target.",
  statement:
    "Given an integer array and a target value, return the indices of two distinct elements whose sum equals the target. You may assume exactly one valid pair exists. A value cannot be used twice.",
  inputFormat: [
    "The first line contains two integers: n and target.",
    "The second line contains n space-separated integers.",
  ],
  outputFormat:
    "Print the two zero-based indices in ascending order, separated by one space.",
  constraints: [
    "2 <= n <= 100,000",
    "-1,000,000,000 <= nums[i] <= 1,000,000,000",
    "-1,000,000,000 <= target <= 1,000,000,000",
    "Exactly one valid answer exists.",
  ],
  examples: [
    {
      id: 1,
      input: "4 9\n2 7 11 15",
      output: "0 1",
      explanation: "nums[0] + nums[1] = 2 + 7 = 9.",
    },
    {
      id: 2,
      input: "3 6\n3 2 4",
      output: "1 2",
      explanation: "nums[1] + nums[2] = 2 + 4 = 6.",
    },
  ],
};

export const starterCode: Record<SupportedLanguage, string> = {
  java: `import java.util.*;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        int n = scanner.nextInt();
        int target = scanner.nextInt();

        int[] nums = new int[n];
        for (int i = 0; i < n; i++) {
            nums[i] = scanner.nextInt();
        }

        Map<Integer, Integer> seen = new HashMap<>();

        for (int i = 0; i < n; i++) {
            int complement = target - nums[i];

            if (seen.containsKey(complement)) {
                System.out.println(seen.get(complement) + " " + i);
                return;
            }

            seen.put(nums[i], i);
        }
    }
}`,
  python: `n, target = map(int, input().split())
nums = list(map(int, input().split()))

seen = {}

for index, value in enumerate(nums):
    complement = target - value

    if complement in seen:
        print(seen[complement], index)
        break

    seen[value] = index
`,
};
