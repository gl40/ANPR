#ifndef FACTORIAL_H
#define FACTORIAL_H

/**
 * Calcule la factorielle d'un nombre entier non négatif.
 * @param n Le nombre dont on veut calculer la factorielle (n >= 0)
 * @return n! (factorielle de n)
 */
unsigned long long factorial(int n);

/**
 * Calcule la factorielle de manière récursive.
 * @param n Le nombre dont on veut calculer la factorielle (n >= 0)
 * @return n! (factorielle de n)
 */
unsigned long long factorialRecursive(int n);

#endif // FACTORIAL_H
