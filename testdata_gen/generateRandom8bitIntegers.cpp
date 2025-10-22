#include <iostream>
#include <cstdlib>
#include <ctime>

// 生成并打印m组，每组n个整数
void generateRandom8bitIntegers(int n, int m) {
    // 初始化随机数种子
    std::srand(std::time(0));

    for (int i = 0; i < m; ++i) {
        std::cout << "Group " << i + 1 << ": ";
        for (int j = 0; j < n; ++j) {
            // 生成0 - 255之间的随机8bit整数
            int randomNum = std::rand() % 256;
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

    generateRandom8bitIntegers(n, m);

    return 0;
}    