#include <oqs/oqs.h>
#include <sodium.h>

int main(void)
{
    return OQS_KEM_keypair_derand == 0 || sodium_init() < 0;
}
