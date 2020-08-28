#include "../Unsecure/App.h"
#include "../Unsecure/Enclave_u.h"
#include <chrono>



#define BUF_SIZE 4096ul
#define NUM_LOOPS 2000000ul
#define IV_SIZE 16
#define CPU_FREQ 3400000000ul

unsigned char key[16] = {'0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5'};
unsigned char iv[16] = {'0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5'};



int main (int argc, char *argv[]) {
    (void) argc;
    (void) argv;

    if(initialize_enclave() < 0){
        printf("Something went horribly wrong trying to initialize the SGX Enclave\n");
    } else {
        printf("Enclave created successfully\n");
    }

    unsigned char buf[BUF_SIZE];
    unsigned char encrypted[BUF_SIZE + IV_SIZE];
    memcpy(encrypted, iv, IV_SIZE);
    memset(buf, '7', BUF_SIZE);

    // Encrypt test buffer
    ecall_encrypt_buffer(global_eid, (void*)(encrypted+IV_SIZE), (void*)buf, BUF_SIZE);


    // Encrypt the buffer for decryption later
    std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
    ecall_benchmark_decryption(global_eid, (void*)encrypted, BUF_SIZE, NUM_LOOPS);
    std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> time_span = std::chrono::duration_cast<std::chrono::duration<double>>(t2 - t1);
    printf("%lf sec\n",  time_span.count());

    printf("%lf cpb\n", (time_span.count() * CPU_FREQ) / (BUF_SIZE * NUM_LOOPS));

    return 0;
}