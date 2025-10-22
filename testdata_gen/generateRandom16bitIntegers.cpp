#include <iostream>
#include <cstdlib>
#include <ctime>

// 生成并打印m组，每组n个整数
void generateRandom16bitIntegers(int n, int m) {
    // 初始化随机数种子
    std::srand(std::time(0));

    for (int i = 0; i < m; ++i) {
        std::cout << "Group " << i + 1 << ": ";
        for (int j = 0; j < n; ++j) {
            // 生成随机16bit整数
            int randomNum = std::rand() % 65536;
            std::cout << randomNum;
            if (j < n - 1) {
                std::cout << ", ";
            }
        }
        std::cout << std::endl;
    }
}

int main() {
    int n, m;
    std::cout << "请输入每组的整数数量 n: ";
    std::cin >> n;
    std::cout << "请输入组数 m: ";
    std::cin >> m;

    generateRandom16bitIntegers(n, m);

    return 0;
}    