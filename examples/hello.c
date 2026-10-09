#include <stdio.h>
#include <stdint.h>

static int calculate(int value) {
    return (value * 3) + 7;
}

int main(void) {
    puts("ReverseLab demo: programa educativo, sem rede.");
    printf("Resultado: %d\n", calculate(11));
    return 0;
}
