#include <iostream>
#include <random>

// 生成并打印 m 组，每组 n 个随机浮点数
void generateRandomFloats(int n, int m) {
    // 创建一个随机数引擎
    std::random_device rd;
    std::mt19937 gen(rd());
    // 创建一个均匀分布，范围是 -100000000 到 100000000
    std::uniform_real_distribution<double> dis(-100000000.0, 100000000.0);

    for (int i = 0; i < m; ++i) {
        std::cout << "Group " << i + 1 << ": ";
        for (int j = 0; j < n; ++j) {
            // 生成一个随机浮点数
            double randomNum = dis(gen);
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
    std::cout << "请输入每组的浮点数数量 n: ";
    std::cin >> n;
    std::cout << "请输入组数 m: ";
    std::cin >> m;

    generateRandomFloats(n, m);

    return 0;
}    