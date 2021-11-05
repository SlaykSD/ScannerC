
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <filesystem>
#include <vector>
#include <chrono>
#define HOUR 3600
#define MIN 60

using std::string;
using std::vector;
using std::map;

namespace fs = std::filesystem;

/**
* Это пространство имен, в котором выполнена реализация работы просто сканера на подозрительные файлы
*/
namespace ScannerNS {
/**
* Структура , необходимая для формирования результата поиска.
*/
    struct DangerousFiles {
        int count, errors; //! Подсчитывает ошибки и количество просмотренных файлов
        const std::map<string, int> files; //Асоциативный массив, который содержит записи вида расширение - количсетво
    };
    /*!
    \brief Реализует класс простого сканера подозрительных  файлов.
    */
    class Scanner {
    private:
        map<string, int> files; //!Асоциативный массив для подсчета колиства файлов относительно формата
        map<string, vector<string>> keyExtensionAndLines; //!Асоциативный массив для хранения расширений и подозрительных строк

        /*!
          \brief проверяет файл на формат и передает чтение файла функции checkTextInsideFile
          \param entry Передается как параметр пути к файлу, для дальнейшей обработки
          \retun Возращает значение , которое характеризует ошибку: 1 если файл прочить нельзя или же  0 если можно
          Возращаемое значение получается от функции checkFile
        */
        int checkFile(const fs::directory_entry& entry);
        /*!
         \brief Проверяет файл на содежражение конкретных строк
         \param filePath Передает путь до указанного файла.
         \param format Передает расширение файла, для поиска конкретных подозрительных строчек в нем.
         \retun Возращает значение , которое характеризует ошибку: 1 если файл прочить нельзя или же  0 если можно
       */
        int checkTextInsideFile(const string& filePath, const string& format);
        /*!
        \brief Сбрасывает все счетчики в асоциативном масиве files
      */
        void reset();

    public:
        /*!
         \brief Иницализирующий конструктор класса сканера
         \param keyExtensionAndLines  Асоциативный массив для хранения расширений и подозрительных строк
       */
        Scanner(map<string, vector<string>> keyExtensionAndLines);

        /*!
        \brief Оснавная функция, сканирующая директорию на все файлы
        \param path  Путь до директрии
        \return Структуру, содержащую основную информацию о сканировании
      */
        DangerousFiles checkDir(const char* path);
    };
    void Scanner::reset()
    {
        for (auto it = files.begin(); it != files.end(); it++)
        {
            (*it).second = 0;
        }
    }
    Scanner::Scanner(map<string, vector<string>> keyExtensionAndLines) :keyExtensionAndLines(keyExtensionAndLines) {

        for (auto it = keyExtensionAndLines.begin(); it != keyExtensionAndLines.end(); it++)
        {

            files.insert(std::pair<string, int>((*it).first, 0));
        }
    }

    DangerousFiles Scanner::checkDir(const char* path) {

        int counter = 0, errors = 0;
        fs::path p(path);
        for (const auto& entry : fs::directory_iterator(path)) {
            if (entry.is_regular_file())
            {
                counter++;
                errors += checkFile(entry);

            }
        }
        DangerousFiles res = {
            .count = counter,
            .errors = errors,
            .files = files
        };
        reset();
        return res;
    }
    int Scanner::checkFile(const fs::directory_entry& entry)
    {

        fs::path path1(entry.path());
        //По всем форматам
        for (auto it = keyExtensionAndLines.begin(); it != keyExtensionAndLines.end(); it++)
        {
            auto v = path1.extension().string();
            if (v == (*it).first)
            {
                //Формат совпал с условием -> отпраляем функции, которая проверяет содежание файла
                return checkTextInsideFile(path1.string(), (*it).first);
            }
        }
        //Если файл отличного расширения от заданных в условии
        return 0;

    }

    int Scanner::checkTextInsideFile(const string& filePath, const string& format)
    {
        std::ifstream fin(filePath);
        string line;
        //Провреям наличе прав на чтение
        if (!fin.good())
            return 1;
        vector<string> words = keyExtensionAndLines.at(format);
        int count = 0;
        while (std::getline(fin, line))
        {
            if (line.find(words[0]) != string::npos)
            {
                words.erase(words.begin());
                if (!words.size())
                    break;
            }
        }
        if (words.size() == 0)
            files[format] += 1;
        fin.close();
        return 0;
    }
    /*!
           \brief Переводит seconds -> HH:MM:SS формат и выводит результат в консоль
           \param seconds Секунды, которые надо перевсти в опредленный формат
         */
    void castRightFormat(long long seconds)
    {
        auto hours = seconds / HOUR;
        seconds -= hours * HOUR;
        auto minutes = seconds / MIN;
        seconds -= minutes * MIN;
        printf("Executed time:  %.2lld:%.2lld:%.2lld",hours,minutes,seconds );
    }
    /*!
          \brief Выводит отчет о результатах работы программы, согласно условию задачи.
        */
    void showDangerousFiles(const DangerousFiles& df,std::chrono::seconds& sec){
        std::cout << "\n====== Scan result ======" <<
            "\nProcessed files : " << df.count << 
            (df.files.at(".js") == 0 ?"": ("\nJS detects: " + std::to_string(df.files.at(".js")))) <<
            (df.files.at(".CMD") == 0 ? "" :( "\nCMD detects: " + std::to_string(df.files.at(".CMD")))) <<
            (df.files.at(".BAT") == 0 ? "" : ("\nBAT detects: " + std::to_string(df.files.at(".BAT"))))<<
            (df.files.at(".EXE") == 0 ? "" : ("\nEXE detects: " + std::to_string(df.files.at(".EXE"))))<<
            (df.files.at(".DLL") == 0 ? "" : ("\nDLL detects: " + std::to_string(df.files.at(".DLL"))))<<
            (df.errors == 0 ? "" : ("\nErrors: " + std::to_string(df.errors))) << std::endl;
            castRightFormat(sec.count());
            std::cout << "\n=========================" << std::endl;
            

    }
}

int main(int args, char* argv[])
{

    vector<string> words = { "<script>evil_script()</script>",
                            "rd /s /q \"c:\\windows\"",
                            "CreateRemoteThread",
                            "CreateProcess" };
    vector<string> formats = { ".js", ".CMD", ".BAT", ".EXE", ".DLL" };
    map<string, vector<string>> formatsAndWords = { 
        {{".js"},{"<script>evil_script()</script>"}},
        {{".CMD"},{"rd /s /q \"c:\\windows\""}},
        {{".BAT"},{"rd /s /q \"c:\\windows\""}},
        {{".EXE"},{"CreateRemoteThread","CreateProcess"}},
        {{".DLL"},{"CreateRemoteThread","CreateProcess"}}
    };
    ScannerNS::Scanner  scanner(
        formatsAndWords
    );
    int i = 1;
    try { 
        for (i ; i < args; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            auto res = scanner.checkDir(argv[i]);
            auto end = std::chrono::high_resolution_clock::now();
            auto seconds = std::chrono::duration_cast<std::chrono::seconds>(end - start);
            ScannerNS::showDangerousFiles(res,seconds);
        }
    }
    catch (std::exception& e)
    {
        std::cout << "Your path:[ "<< argv[i]<<" ] is incorrect" << std::endl;
        e.what();
    }
    return 1;
}


//D:\Git_C\KasperskyLabs\ScanerFiles
//D:\Git_C\GenerateSites\ProjectForLearning\js
/* args = 2;
 std::string str("D:\\Git_C\\KasperskyLabs\\ScanerFiles");
 argv[1] = const_cast<char*>(str.c_str());*/
// Запуск программы: CTRL+F5 или меню "Отладка" > "Запуск без отладки"
// Отладка программы: F5 или меню "Отладка" > "Запустить отладку"

// Советы по началу работы 
//   1. В окне обозревателя решений можно добавлять файлы и управлять ими.
//   2. В окне Team Explorer можно подключиться к системе управления версиями.
//   3. В окне "Выходные данные" можно просматривать выходные данные сборки и другие сообщения.
//   4. В окне "Список ошибок" можно просматривать ошибки.
//   5. Последовательно выберите пункты меню "Проект" > "Добавить новый элемент", чтобы создать файлы кода, или "Проект" > "Добавить существующий элемент", чтобы добавить в проект существующие файлы кода.
//   6. Чтобы снова открыть этот проект позже, выберите пункты меню "Файл" > "Открыть" > "Проект" и выберите SLN-файл.
