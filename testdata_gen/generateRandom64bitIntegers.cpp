#include <iostream>
#include <cstdint>
#include <random>

// 生成并打印 m 组，每组 n 个整数
void generateRandom64bitIntegers(int n, int m) {
    // 创建一个随机数引擎
    std::random_device rd;
    std::mt19937_64 gen(rd());
    // 创建一个均匀分布，范围是 64 bit整数的整个范围
    std::uniform_int_distribution<uint64_t> dis(0, UINT64_MAX);

    for (int i = 0; i < m; ++i) {
        std::cout << "Group " << i + 1 << ": ";
        for (int j = 0; j < n; ++j) {
            // 生成一个 64 位随机整数
            uint64_t randomNum = dis(gen);
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

    generateRandom64bitIntegers(n, m);

    return 0;
}    