#include "../Unsecure/App.h"
#include "../Unsecure/Enclave_u.h"

int main (int argc, char *argv[]) {
    (void) argc;
    (void) argv;

    if(initialize_enclave() < 0){
        printf("Something went horribly wrong trying to initialize the SGX Enclave\n");
    } else {
        printf("enclave CREATED\n");
    }

    return 0;
}