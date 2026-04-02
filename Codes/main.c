#include "common.h"

int main(void)
{
    WSADATA wsa;
    int choice;
    int ch;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }

    srand((unsigned)time(NULL));

    printf("TCP/UDP FILE TRANSFER - SNR SIMULATION\n");
    printf("======================================\n\n");
    printf("1 - Server\n");
    printf("2 - Client\n\n");
    printf("Choice: ");
    fflush(stdout);

    if (scanf("%d", &choice) != 1) {
        printf("Invalid input.\n");
        WSACleanup();
        return 1;
    }


    do { ch = getchar(); } while (ch != '\n' && ch != EOF);
    printf("\n");

    if (choice == 1) run_server();
    else if (choice == 2) run_client();
    else printf("Invalid choice.\n");

    WSACleanup();
    return 0;
}

