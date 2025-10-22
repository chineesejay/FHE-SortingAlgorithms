#include <iostream>
#include <tfhe/tfhe_core.h>
#include <iomanip>
#include <tfhe/tfhe.h>
#include <time.h>



using namespace std;

int arrayLength = 0;
int int_bits = 16;
typedef int16_t intn_t;
int* plaintext;
TFheGateBootstrappingSecretKeySet *key;

void compare_bits(LweSample *result, const LweSample *a, const LweSample *b, const LweSample *lsb_carry, LweSample *tmp, const TFheGateBootstrappingCloudKeySet *bk)
{
    bootsXNOR(tmp, a, b, bk);
    bootsMUX(result, tmp, lsb_carry, b, bk);
}

void minimum(LweSample *result, const LweSample *a, const LweSample *b, const int bits, const TFheGateBootstrappingCloudKeySet *bk,TFheGateBootstrappingSecretKeySet *key )
{
    // find the minimum of a and b
    LweSample *tmps = new_gate_bootstrapping_ciphertext_array(4, bk->params);

    //initial the carry to 0

    bootsCONSTANT(&tmps[0], 0, bk);

    for (int i = 0; i < 15; i++)
        compare_bits(&tmps[0], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    bootsNOT(&tmps[2],&a[15],bk);
    bootsNOT(&tmps[3],&b[15],bk);
    compare_bits(&tmps[0], &tmps[2], &tmps[3], &tmps[0], &tmps[1], bk);

    for (int i = 0; i < 16; i++)
        bootsMUX(&result[i], &tmps[0], &a[i], &b[i], bk);
    delete_gate_bootstrapping_ciphertext_array(4, tmps);
}

void LweSwap( LweSample *a, LweSample *b, const int bits, const TFheGateBootstrappingCloudKeySet *bk)
{
    // find the minimum of a and b
    LweSample *tmps = new_gate_bootstrapping_ciphertext_array(4, bk->params);
    LweSample *resultSmall = new_gate_bootstrapping_ciphertext_array(bits, bk->params);
    LweSample *resultLarge = new_gate_bootstrapping_ciphertext_array(bits, bk->params);

    //initial the carry to 0
    bootsCONSTANT(&tmps[0], 0, bk);

    for (int i = 0; i < bits-1; i++)
        compare_bits(&tmps[0], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    bootsNOT(&tmps[2],&a[bits-1],bk);
    bootsNOT(&tmps[3],&b[bits-1],bk);
    compare_bits(&tmps[0], &tmps[2], &tmps[3], &tmps[0], &tmps[1], bk);

    for (int i = 0; i < bits; i++)
        bootsMUX(&resultSmall[i], &tmps[0], &a[i], &b[i], bk);
    bootsNOT(tmps, tmps, bk);
    for (int i = 0; i < bits; i++)
        bootsMUX(&resultLarge[i], &tmps[0], &a[i], &b[i], bk);

    for (int i = 0; i < bits; i++)
   	 bootsCOPY(&a[i],&resultSmall[i], bk);
    for (int i = 0; i < bits; i++)
   	 bootsCOPY(&b[i],&resultLarge[i], bk);

    delete_gate_bootstrapping_ciphertext_array(4, tmps);
    delete_gate_bootstrapping_ciphertext_array(bits, resultSmall);
    delete_gate_bootstrapping_ciphertext_array(bits, resultLarge);
}


void bubbleSort (LweSample *Lwearray[], int length, const int bits, const TFheGateBootstrappingCloudKeySet *bk){

    for(int i =0;i<length-1;i++){
        for(int j= 0;j<length-i-1; j++){
            LweSwap(Lwearray[j],Lwearray[j+1],bits,bk);
        }
    }

}

void csort (LweSample *Lwearray[], int length, const int bits, const TFheGateBootstrappingCloudKeySet *bk){
	for(int i = length - 1;i>0;i--){
	   for( int j = 0; j<i;j++){
	   	 LweSwap(Lwearray[j],Lwearray[i],bits,bk);
	   }
	}
}

// 实现一个加法器
void bootsResult(LweSample *result,                         // 用于存放结果
                const LweSample *ca,                      // 输入加数 a
                const LweSample *cb,                      // 输入加数 b
                const LweSample *cc,                      // 输入进位 c

                const LweParams *LWEparams,                 // 输入 LWE 参数


                const TFheGateBootstrappingCloudKeySet *bk)                 // 输入 LWE 密钥（仅适用公钥部分）
{
    LweSample *temp_result = new_LweSample(LWEparams);

    static const Torus32 AndConst = modSwitchToTorus32(3, 8);
    const Torus32 mu = 0;

    lweNoiselessTrivial(temp_result, AndConst, LWEparams);

    lweAddTo(temp_result, ca, LWEparams);
    lweAddTo(temp_result, cb, LWEparams);
    lweAddTo(temp_result, cc, LWEparams);

    lweAddTo(temp_result, ca, LWEparams);
    lweAddTo(temp_result, cb, LWEparams);
    lweAddTo(temp_result, cc, LWEparams);

    lweAddTo(temp_result, AndConst, LWEparams);

    tfhe_bootstrap(result,bk,mu,temp_result);

    delete_LweSample(temp_result);
    return;
}

// 实现一个半加器
void simiAdder2(LweSample *result,                         // 用于存放结果
                const LweSample *ca,                      // 输入加数 a
                const LweSample *cb,                      // 输入加数 b
                const LweSample *cc,                      // 输入进位 c

                const LweParams *LWEparams,                 // 输入 LWE 参数


                const TFheGateBootstrappingCloudKeySet *bk)                 // 输入 LWE 密钥（仅适用公钥部分）
{
    LweSample *temp_result = new_LweSample(LWEparams);
    bootsXOR(temp_result,ca, cb, bk);
    bootsXOR(result,temp_result, cc, bk);

    delete_LweSample(temp_result);
    return;
}

/*
\begin{equation}\label{eq-4}
     carry=C^i_a+C^i_b+carry
\end{equation}
*/
// 实现一个进位器
void bootsCarry(LweSample *result,                       // 用于存放结果
                const LweSample *ca,                      // 输入加数 a
                const LweSample *cb,                      // 输入加数 b
                const LweSample *cc,                      // 输入进位 c

                const LweParams *LWEparams,                 // 输入 LWE 参数

                const TFheGateBootstrappingCloudKeySet *bk)                 // 输入 LWE 密钥（仅适用公钥部分）
{
    LweSample *temp_result = new_LweSample(LWEparams);
    const Torus32 mu = 0;

    lweAddTo(temp_result, ca, LWEparams);
    lweAddTo(temp_result, cb, LWEparams);
    lweAddTo(temp_result, cc, LWEparams);

    tfhe_bootstrap(result,bk,mu,temp_result);

    delete_LweSample(temp_result);
    return;
}

// 实现一个进位器
void simiCounter2(LweSample *result,                       // 用于存放结果
                const LweSample *ca,                      // 输入加数 a
                const LweSample *cb,                      // 输入加数 b
                const LweSample *cc,                      // 输入进位 c

                const LweParams *LWEparams,                 // 输入 LWE 参数

                const TFheGateBootstrappingCloudKeySet *bk)                 // 输入 LWE 密钥（仅适用公钥部分）
{
    LweSample *temp_result2 = new_LweSample(LWEparams);
    LweSample *temp_result3 = new_LweSample(LWEparams);
    LweSample *temp_result4 = new_LweSample(LWEparams);
    LweSample *temp_result5 = new_LweSample(LWEparams);
    bootsAND(temp_result2, ca, cb, bk);
    bootsAND(temp_result3, ca, cc, bk);
    bootsAND(temp_result4, cb, cc, bk);
    bootsOR(temp_result5, temp_result2, temp_result3, bk);
    bootsOR(result, temp_result5, temp_result4, bk);
    delete_LweSample(temp_result2);
    delete_LweSample(temp_result3);
    delete_LweSample(temp_result4);
    delete_LweSample(temp_result5);
    return;
}


// 实现一位加法器
void oneBitAdder(LweSample *result1,                      // 用于存放结果
                LweSample *result2,                       // 用于存放进位
                const LweSample *ca,                      // 输入加数 a
                const LweSample *cb,                      // 输入加数 b
                const LweSample *cc,                      // 输入进位 c
                const LweParams *LWEparams,                 // 输入 LWE 参数
              const TFheGateBootstrappingCloudKeySet *bk)                 // 输入 LWE 密钥（仅适用公钥部分）
{
    bootsResult(result1, ca, cb, cc, LWEparams, bk);
    bootsCarry(result2, ca, cb, cc, LWEparams,bk);
    return;
}

// 实现一位加法器
void oneBitAdder1(LweSample *result1,                      // 用于存放结果
                LweSample *result2,                       // 用于存放进位
                const LweSample *ca,                      // 输入加数 a
                const LweSample *cb,                      // 输入加数 b
                const LweSample *cc,                      // 输入进位 c
                const LweParams *LWEparams,                 // 输入 LWE 参数
              const TFheGateBootstrappingCloudKeySet *bk)                 // 输入 LWE 密钥（仅适用公钥部分）
{
    simiAdder(result1, ca, cb, cc, LWEparams, bk);
    simiCounter(result2, ca, cb, cc, LWEparams,bk);
    return;
}

LweSample* isGreater(LweSample *isGreat, const LweSample *a, const LweSample *b, const int bits, const TFheGateBootstrappingCloudKeySet *bk)
{
    // find the minimum of a and b
    LweSample *tmps = new_gate_bootstrapping_ciphertext_array(4, bk->params);
   // LweSample *tmps1 = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    //initial the carry to 0
    bootsCONSTANT(&tmps[0], 0, bk);

    for (int i = 0; i < bits-1; i++)
        compare_bits(&tmps[0], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    bootsNOT(&tmps[2],&a[bits-1],bk);
    bootsNOT(&tmps[3],&b[bits-1],bk);
    compare_bits(&tmps[0], &tmps[2], &tmps[3], &tmps[0], &tmps[1], bk);

    //tmps[0] = 0 represents a is larger, 1 b is larger

    bootsCOPY(&isGreat[0],&tmps[0],bk);
    delete_gate_bootstrapping_ciphertext_array(4, tmps);
    return isGreat;
    //delete_gate_bootstrapping_ciphertext_array(2, tmps1);
}


void additionSort(LweSample *Lwearray[], LweSample *index[],int length, const int bits, const TFheGateBootstrappingCloudKeySet *bk){
    int i1 = length;
    int bit_length=1;
    while(i1/2!=0){
        bit_length++;
        i1/=2;
    }
    LweSample *position = new_gate_bootstrapping_ciphertext_array(bit_length, bk->params);
    LweSample *isGreat = new_gate_bootstrapping_ciphertext_array(bit_length, bk->params);
    LweSample *result = new_gate_bootstrapping_ciphertext_array(bit_length, bk->params);

    for (int i = 0; i < bit_length; i++)
    {
        bootsCONSTANT(&isGreat[i], 0, bk);
    }

    for(int i =0;i<length;i++){
        //k' = 0'
          LweSample *temp_adder = new_LweSample(bk->params->in_out_params);
	     const Torus32 OrNYConst = modSwitchToTorus32(-1, 8);
    	    lweNoiselessTrivial(temp_adder, OrNYConst, bk->params->in_out_params);
        for (int i = 0; i < bit_length; i++)
        {
            bootsCONSTANT(&position[i], 0, bk);

        }
        for(int j =i+1; j<length;j++ ){
           if(j!=i+1){
                for (int i = 0; i < bit_length; i++)
                {
                    bootsCOPY(&position[i],&result[i], bk);

                }
           }
            //比较Lwearray[j]和Lwearray的大小
           isGreater(isGreat,Lwearray[j],Lwearray[i],bits,bk);

            for (int32_t i = 0; i < bit_length; i++){
       	        oneBitAdder(&result[i] ,temp_adder, &position[i],&isGreat[i], temp_adder, bk->params->in_out_params, bk);
        	}
        }
        //shuchu position

        if(i!=length-1){
           	for (int k = 0; k < bit_length; k++)
		    {
		        bootsCOPY(&index[i][k],&result[k], bk);
	    	}
        }

    }
    delete_gate_bootstrapping_ciphertext_array(bit_length, position);
    delete_gate_bootstrapping_ciphertext_array(bit_length, isGreat);
    delete_gate_bootstrapping_ciphertext_array(bit_length, result);

}

void additionSort1(LweSample *Lwearray[], LweSample *index[],int length, const int bits, const TFheGateBootstrappingCloudKeySet *bk){
    int i1 = length;
    int bit_length=1;
    while(i1/2!=0){
        bit_length++;
        i1/=2;
    }
    LweSample *position = new_gate_bootstrapping_ciphertext_array(bit_length, bk->params);
    LweSample *isGreat = new_gate_bootstrapping_ciphertext_array(bit_length, bk->params);
    LweSample *result = new_gate_bootstrapping_ciphertext_array(bit_length, bk->params);

    for (int i = 0; i < bit_length; i++)
    {
        bootsCONSTANT(&isGreat[i], 0, bk);
    }

    for(int i =0;i<length;i++){
        //k' = 0'
          LweSample *temp_adder = new_LweSample(bk->params->in_out_params);
	     const Torus32 OrNYConst = modSwitchToTorus32(-1, 8);
    	    lweNoiselessTrivial(temp_adder, OrNYConst, bk->params->in_out_params);
        for (int i = 0; i < bit_length; i++)
        {
            bootsCONSTANT(&position[i], 0, bk);

        }
        for(int j =i+1; j<length;j++ ){
           if(j!=i+1){
                for (int i = 0; i < bit_length; i++)
                {
                    bootsCOPY(&position[i],&result[i], bk); 

                }
           }
            //比较Lwearray[j]和Lwearray的大小
           isGreater(isGreat,Lwearray[j],Lwearray[i],bits,bk);

            for (int32_t i = 0; i < bit_length; i++){
       	        oneBitAdder1(&result[i] ,temp_adder, &position[i],&isGreat[i], temp_adder, bk->params->in_out_params, bk);
        	}
        }
        //shuchu position

        if(i!=length-1){
           	for (int k = 0; k < bit_length; k++)
		    {
		        bootsCOPY(&index[i][k],&result[k], bk);
	    	}
        }

    }
    delete_gate_bootstrapping_ciphertext_array(bit_length, position);
    delete_gate_bootstrapping_ciphertext_array(bit_length, isGreat);
    delete_gate_bootstrapping_ciphertext_array(bit_length, result);

}

//User method
bool signal(LweSample * sign){
	int ai = bootsSymDecrypt(&sign[0], key);
	if(ai==0) return true;
	return false;
}

void quickSort(LweSample *a[], int low ,int high,int bits, const TFheGateBootstrappingCloudKeySet *bk)
{

	if(low<high)  //判断是否满足排序条件，递归的终止条件
	{
	    int i = low, j = high;   //把待排序数组元素的第一个和最后一个下标分别赋值给i,j，使用i,j进行排序；
            LweSample *x = new_gate_bootstrapping_ciphertext_array(bits, bk->params);
            LweSample *isGreat = new_gate_bootstrapping_ciphertext_array(bits, bk->params);
//		int x = a[low];    //将待排序数组的第一个元素作为哨兵，将数组划分为大于哨兵以及小于哨兵的两部分

            for(int i =0;i<bits;i++){
                bootsCOPY(&x[i],&a[low][i], bk);
            }
	     while(i<j)
	       {
		  while(i<j && signal(isGreater(isGreat,a[j] , x,bits,bk))) j--;  //从最右侧元素开始，如果比哨兵大，那么它的位置就正确，然后判断前一个元素，直到不满足条件

		  if(i<j) {
		  //a[i++] = a[j];   //把不满足位次条件的那个元素值赋值给第一个元素，（也即是哨兵元素，此时哨兵已经保存在x中，不会丢失）并把i的加1
			for(int k =0;k<bits;k++){

			    bootsCOPY(&a[i][k],&a[j][k], bk);

			}
			i++;
		  }
		  while(i<j && signal(isGreater(isGreat,x,a[i],bits,bk))) i++; //换成左侧下标为i的元素开始与哨兵比较大小，比其小，那么它所处的位置就正确，然后判断后一个，直到不满足条件 a[i] <= x
		  if(i<j){
		  	for(int k =0;k<bits;k++){
			    bootsCOPY(&a[j][k],&a[i][k], bk);
			}
			j--;
		  } //a[j--] = a[i];  //把不满足位次条件的那个元素值赋值给下标为j的元素，（下标为j的元素已经保存到前面，不会丢失）并把j的加1
		}
	       // a[i] = x;   //完成一次排序，把哨兵赋值到下标为i的位置，即前面的都比它小，后面的都比它大
	       for(int k =0;k<bits;k++){
		  bootsCOPY(&a[i][k],&x[k], bk);
		}
		quickSort(a, low ,i-1,bits,bk);  //递归进行哨兵前后两部分元素排序 ， low,high的值不发生变化，i处于中间
		quickSort(a, i+1 ,high,bits,bk);
	}
}

void cin_numbers(){
	cout<<"| Please input array length: "<<"     |"<<endl;
	cin>>arrayLength;
	plaintext=new int[arrayLength];
	cout<<"| Please input array: "<<"            |"<<endl;
	for(int i =0;i<arrayLength;i++){
		cin>>plaintext[i];
	}
}
void cin_bits(){

	bool flag = true;
	int selection;
	int large ;
	cout<<"| Please choose number bis: "<<"      |"<<endl;
	cout<<"| case 1:             8 bit       |"<<endl;
	cout<<"| case 2:             16bit       |"<<endl;
	cout<<"| case 3:             32bit       |"<<endl;
	do{
	    cin>>selection;
	    switch (selection){
	        case 1:
	            flag = true;
                {
                    large = 127;
                    for(int i =0;i<arrayLength;i++){
                        if(abs(plaintext[i])>large)
                            flag =false;
                    }
                    if(flag == false)
                        cout<<"Bit error,please input again"<<endl;
                    else
                    {
                        int_bits = 8;
                        typedef int8_t intn_t;
                    }

                    break;
                }
	        case 2:
	             flag =true;
                 {
                    large = 32767;

                    for(int i =0;i<arrayLength;i++){
                        if(abs(plaintext[i])>large)
                            flag =false;
                     }
                    if(flag == false)
                        cout<<"Bit error,please input again"<<endl;
                    else{
                        int_bits = 16;
                        typedef int16_t intn_t;
                    }
                    break;
                 }
	        case 3:
	             flag = true;
                 {
                    large = 2147483647;
                    for(int i =0;i<arrayLength;i++){
                         if(abs(plaintext[i])>large)
                            flag =false;
                    }
                    if(flag == false)
                         cout<<"Bit error,please input again"<<endl;
                    else{
                       int_bits = 32;
                       typedef int32_t intn_t;
                   }

                   break;
                }
	        default:
	            flag = false;
	    }
	}while(!flag);
}

void coutAnswer(LweSample *ciphertext[],TFheGateBootstrappingSecretKeySet *key){
	 cout << "answer: [";
	  if(int_bits == 8){
	       for(int j = 0;j<arrayLength;j++){

	    	    int8_t answer = 0;
                for (int i = 0; i < int_bits; i++)
                {
                    int ai = bootsSymDecrypt(&ciphertext[j][i], key);
                    answer |= (ai << i);
                }

                if(j!=arrayLength-1){
                    cout<< (int)answer <<",";
                }else{
                    cout<< (int)answer <<"]"<<endl;
                }
		    }
        }
        else if(int_bits == 16){
            for(int j = 0;j<arrayLength;j++){

	    	    int16_t answer = 0;
                for (int i = 0; i < int_bits; i++)
                {
                    int ai = bootsSymDecrypt(&ciphertext[j][i], key);
                    answer |= (ai << i);
                }

                if(j!=arrayLength-1){
                    cout<< (int)answer <<",";
                }else{
                    cout<< (int)answer <<"]"<<endl;
                }
            }
        }
         else if(int_bits == 32){
            for(int j = 0;j<arrayLength;j++){

	    	    int32_t answer = 0;
                for (int i = 0; i < int_bits; i++)
                {
                    int ai = bootsSymDecrypt(&ciphertext[j][i], key);
                    answer |= (ai << i);
                }
                if(j!=arrayLength-1){
                    cout<< (int)answer <<",";
                }else{
                    cout<< (int)answer <<"]"<<endl;
                }
            }
        }
}

int main()
{
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = {14569,165,155,3698,2541};
    tfhe_random_generator_setSeed(seed, 3);
    key = new_random_gate_bootstrapping_secret_keyset(params);


    while (true)
    {
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| Fully Homomorphic Sorting Algorithm                     |" << endl;
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| Please select a sorting algorithm below.                |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;
        cout << "| 1. Bubble Sort                                          |" << endl;
        cout << "| 2. Quick Sort                                           |" << endl;
        cout << "| 3. Addition Sort                                        |" << endl;
        cout << "| 4. Input Bits              | Current Bits: "<<setw(2)<<int_bits<<"           |" << endl;
        cout << "| 5. Input Sorting Arrays                                 |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;


        cout<<"ArrayLength: "<<setw(7)<<arrayLength<<endl;
        cout << "[";
        for(int j = 0;j<arrayLength;j++){

            if(j!=arrayLength-1){
                cout<< (int)plaintext[j]<<",";
            }else{
                cout<< (int)plaintext[j] ;
            }
	    }
	    cout<<"]"<<endl;
        int selection = 0;
        bool valid = true;
        do
        {
            cout << endl << "> Run example (1 ~ 5) or exit (0): ";
            if (!(cin >> selection))
            {
                valid = false;
            }
            else if (selection < 0 || selection > 5)
            {
                valid = false;
            }
            else
            {
                valid = true;
            }
            if (!valid)
            {
                cout << "  [Beep~~] valid option: type 0 ~ 5" << endl;
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            }
        } while (!valid);

        switch (selection)
        {
        case 1:{
            if(arrayLength==0){
                cout << "The current array length is 0 !"<<endl;
                break;
            }
            cout << "ALice: Hi there! Today, I will ask the cloud what is the sorted result of array [";
            for(int i = 0 ;i<arrayLength-1;i++){
                cout<<plaintext[i]<<",";
            }
            cout<<plaintext[arrayLength-1]<<"]"<<endl;

            LweSample *ciphertext[arrayLength];
            for(int i =0;i<arrayLength;i++){
                ciphertext[i] = new_gate_bootstrapping_ciphertext_array(int_bits, params);
            }


            cout << " start to encrypt.... " << endl;
            for (int i = 0; i < int_bits-1; i++)
            {
                for(int j =0;j<arrayLength;j++){
                    bootsSymEncrypt(&ciphertext[j][i], (plaintext[j] >> i) & 1, key);
                }

            }
            for(int j =0;j<arrayLength;j++){
                    bootsSymEncrypt(&ciphertext[j][int_bits-1], (plaintext[j] >> 31) & 1, key);
            }

            cout<<"Cloud: Now , I will compute the sorted array homomorphically....."<<endl;
            //bootstapping key
            const TFheGateBootstrappingCloudKeySet *bk = &(key->cloud);
            time_t t0 = clock();


	        bubbleSort(ciphertext,arrayLength,int_bits,bk);


            time_t t1 = clock();


    	    cout<<"compute the sorted circuit in "<< (t1-t0)/CLOCKS_PER_SEC <<" secs"<<endl;
            break;}

        case 2:{
             if(arrayLength==0){
                cout << "The current array length is 0 !"<<endl;
                break;
            }
            cout << "ALice: Hi there! Today, I will ask the cloud what is the sorted result of array [";
            for(int i = 0 ;i<arrayLength-1;i++){
                cout<<plaintext[i]<<",";
            }
            cout<<plaintext[arrayLength-1]<<"]"<<endl;

            LweSample *ciphertext[arrayLength];
             for(int i =0;i<arrayLength;i++){
                ciphertext[i] = new_gate_bootstrapping_ciphertext_array(int_bits, params);
            }
            cout << " start to encrypt.... " << endl;
            for (int i = 0; i < int_bits-1; i++)
            {
                for(int j =0;j<arrayLength;j++){
                    bootsSymEncrypt(&ciphertext[j][i], (plaintext[j] >> i) & 1, key);
                }

            }
            for(int j =0;j<arrayLength;j++){
                    bootsSymEncrypt(&ciphertext[j][int_bits-1], (plaintext[j] >> 31) & 1, key);
            }

            cout<<"Cloud: Now , I will compute the sorted array homomorphically....."<<endl;
            //bootstapping key
            const TFheGateBootstrappingCloudKeySet *bk = &(key->cloud);
            time_t t0 = clock();
            quickSort(ciphertext, 0 ,arrayLength-1,int_bits, bk);
            time_t t1 = clock();

        	cout<<"compute the sorted circuit in "<< (t1-t0)/CLOCKS_PER_SEC <<" secs"<<endl;
            coutAnswer(ciphertext,key);

            break;
        }

        case 3:{
             if(arrayLength==0){
                cout << "The current array length is 0 !"<<endl;
                break;
             }
             cout << "ALice: Hi there! Today, I will ask the cloud what is the sorted result of array [";
             for(int i = 0 ;i<arrayLength-1;i++){
                 cout<<plaintext[i]<<",";
             }
             cout<<plaintext[arrayLength-1]<<"]"<<endl;

             LweSample *ciphertext[arrayLength];
             for(int i =0;i<arrayLength;i++){
                ciphertext[i] = new_gate_bootstrapping_ciphertext_array(int_bits, params);
             }


            cout << " start to encrypt.... " << endl;
            for (int i = 0; i < int_bits-1; i++)
            {
                for(int j =0;j<arrayLength;j++){
                    bootsSymEncrypt(&ciphertext[j][i], (plaintext[j] >> i) & 1, key);
                }

            }
            for(int j =0;j<arrayLength;j++){
                bootsSymEncrypt(&ciphertext[j][int_bits-1], (plaintext[j] >> 31) & 1, key);
            }

            cout<<"Cloud: Now , I will compute the sorted array homomorphically....."<<endl;
            //bootstapping key
            const TFheGateBootstrappingCloudKeySet *bk = &(key->cloud);
            time_t t0 = clock();
            LweSample *index[arrayLength-1]; //进行云端加密计算的加密下标,只需要arrayLength-1位
            int indexInt[arrayLength]={0}; //解密后的进行云端加密计算的解密下标
            int indexPlace[arrayLength] ;//放置相应排序位置对应的明文
            for(int i =0;i<arrayLength;i++){
                indexPlace[i] = -1;
            }
            int i1 = arrayLength;
            int bit_length=1; //加密下标表示所需的bit位
            while(i1/2!=0){
                bit_length++;
                i1/=2;
            }
            for(int i =0;i<arrayLength-1;i++){
                index[i] = new_gate_bootstrapping_ciphertext_array(bit_length, params);
            }
            additionSort(ciphertext,index,arrayLength,int_bits,bk);


            time_t t1 = clock();
            cout<<"compute the sorted circuit in "<< (t1-t0)/CLOCKS_PER_SEC <<" secs"<<endl;

            for(int i = 0;i<arrayLength-1;i++){
                LweSample *q = index[i];
                for(int j = 0 ; j<bit_length;j++){
                      int ai = bootsSymDecrypt(&q[j], key);

                         indexInt[i] |= (ai << j);

                }
            }
             for(int i =0;i<arrayLength;i++){
                 indexInt[i]+=1;//将每个下标值+1，最小值从1开始
             }
            for(int i=0;i<arrayLength;i++){
                for(int j =0;j<arrayLength;j++){
                    if(indexPlace[j]==-1){
                        if(--indexInt[i]==0)
                        indexPlace[j] = plaintext[i]; //place plaintext[i] on it;
                    }
                }
            }


            cout << "answer: [";
            for(int j = 0;j<arrayLength;j++){


                if(j!=arrayLength-1){
                    cout<<indexPlace[j] <<",";
                }else{
                    cout<<indexPlace[j] <<"]"<<endl;
                }
            }

            break;}

            case 4:
                cin_bits();
                break;

            case 5:
                cin_numbers();
                break;

            case 0:
                return 0;
        }
    }
    return 0;
}

