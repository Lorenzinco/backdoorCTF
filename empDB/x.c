#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define DEVICE_PATH "/dev/challenge"  // Replace with the actual path of your device

#define FUNCTION_1 0x13370003
#define FUNCTION_2 0x322371588
#define FUNCTION_3 0X322371586
#define FUNCTION_4 0X322371585

// Example IOCTL command (replace with your specific IOCTL command)
#define MY_IOCTL_COMMAND _IO('k', 1)

int main() {
    int fd;

    // Open the device file
    fd = open(DEVICE_PATH, O_RDWR);
    if (fd == -1) {
        perror("Error opening the device");
        return EXIT_FAILURE;
    }

    // Perform IOCTL operation
    if (ioctl(fd, MY_IOCTL_COMMAND) == -1) {
        perror("IOCTL failed");
        close(fd);
        return EXIT_FAILURE;
    }

    // Close the device file
    close(fd);

    return EXIT_SUCCESS;
}