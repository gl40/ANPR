#include "Factorial.h"

unsigned long long factorial(int n) {
    if (n < 0) {
        return 0;
    }

    unsigned long long result = 1;
    for (int i = 2; i <= n; i++) {
        result *= i;
    }
    return result;
}

unsigned long long factorialRecursive(int n) {
    if (n < 0) {
        return 0;
    }
    if (n <= 1) {
        return 1;
    }
    return n * factorialRecursive(n - 1);
}
