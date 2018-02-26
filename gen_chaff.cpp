#include "rot13.h"

#include <random>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cctype>


const unsigned CHAFF_SIZE = 10000;

class ChaffGenerator
{
private:
    std::random_device randomDev;

    unsigned realPasswordIndex;
    unsigned realFlagIndex;
    unsigned fakePasswordIndex;
    unsigned fakeFlagIndex;

    std::vector<std::string> passwords;
    std::vector<std::string> flags;

    std::vector<std::string> words;
    std::vector<std::string> specialWords = {"So", "Such", "Many", "Much", "Very"};

public:
    ChaffGenerator(const std::string& wordsListFileName)
    {
        this->realPasswordIndex = this->randomDev() % CHAFF_SIZE;
        do
        {
            this->fakePasswordIndex = this->randomDev() % CHAFF_SIZE;
        }
        while (this->fakePasswordIndex == this->realPasswordIndex);

        this->realFlagIndex = this->randomDev() % CHAFF_SIZE;
        do
        {
            this->fakeFlagIndex = this->randomDev() % CHAFF_SIZE;
        }
        while (this->fakeFlagIndex == this->realFlagIndex);

        this->passwords.reserve(CHAFF_SIZE);
        this->flags.reserve(CHAFF_SIZE);

        this->loadWordsList(wordsListFileName);
    }

    void generateChaff()
    {
        for (unsigned i = 0; i < CHAFF_SIZE - 2; i++)
        {
            std::string password;
            if (i == this->realPasswordIndex)
            {
                password = "AlwaysDoubleCheck";
            }
            else if (i == this->fakePasswordIndex)
            {
                password = "BigBrotherIsWatchingYou";
            }
            else
            {
                unsigned randomPasswordWordCount = this->randomDev() % 5 + 2;
                for (int j = 0; j < randomPasswordWordCount; j++)
                {
                    password += this->getRandomWord();
                }
            }
            this->passwords.push_back(std::move(password));

            std::string flag;
            if (i == this->realFlagIndex)
            {
                flag = "VerySuspicionManyInquiryWow";
            }
            else if (i == this->fakeFlagIndex)
            {
                flag = "MuchDebuggerSoStaticAnalisysWow";
            }
            else
            {
                flag = this->getRandomSpecialWord() + this->getRandomWord() + this->getRandomSpecialWord() + this->getRandomWord() + "Wow";
            }
            this->flags.push_back(std::move(flag));
        }
    }

    void generateSource()
    {
        this->generateHeader();
        this->generateSourceFile();
    }

private:
    void loadWordsList(const std::string& wordsListFileName)
    {
        std::ifstream wordsListFile(wordsListFileName);

        for (std::string line; std::getline(wordsListFile, line); )
        {
            line[0] = std::toupper(line[0]);
            this->words.push_back(std::move(line));
        }
    }

    const std::string& getRandomWord()
    {
        return this->words[this->randomDev() % this->words.size()];
    }

    const std::string& getRandomSpecialWord()
    {
        return this->specialWords[this->randomDev() % this->specialWords.size()];
    }

    void generateHeader()
    {
        std::ofstream headerFile("chaff.h");

        headerFile << "#ifndef __CTF_PTOOIE_CHAFF_H__"                          << std::endl;
        headerFile << "#define __CTF_PTOOIE_CHAFF_H__"                          << std::endl;
        headerFile << ""                                                        << std::endl;
        headerFile << ""                                                        << std::endl;
        headerFile << "#ifdef __cplusplus"                                      << std::endl;
        headerFile << "extern \"C\""                                            << std::endl;
        headerFile << "{"                                                       << std::endl;
        headerFile << "#endif"                                                  << std::endl;
        headerFile << ""                                                        << std::endl;
        headerFile << "extern const char* const passwords[];"                   << std::endl;
        headerFile << "extern const char* const flags[];"                       << std::endl;
        headerFile << ""                                                        << std::endl;
        headerFile << "#ifdef __cplusplus"                                      << std::endl;
        headerFile << "}"                                                       << std::endl;
        headerFile << "#endif"                                                  << std::endl;
        headerFile << ""                                                        << std::endl;
        headerFile << ""                                                        << std::endl;
        headerFile << "#define REAL_PASSWORD_INDEX " << this->realPasswordIndex << std::endl;
        headerFile << "#define REAL_FLAG_INDEX " << this->realFlagIndex         << std::endl;
        headerFile << "#define FAKE_PASSWORD_INDEX " << this->fakePasswordIndex << std::endl;
        headerFile << "#define FAKE_FLAG_INDEX " << this->fakeFlagIndex         << std::endl;
        headerFile << ""                                                        << std::endl;
        headerFile << ""                                                        << std::endl;
        headerFile << "#endif"                                                  << std::endl;

        if (headerFile.fail() || headerFile.bad())
        {
            throw std::runtime_error("Cannot create header file.");
        }
    }

    void generateSourceFile()
    {
        std::ofstream sourceFile("chaff.c");

        sourceFile << "#include \"chaff.h\""                << std::endl;
        sourceFile << ""                                    << std::endl;
        sourceFile << ""                                    << std::endl;
        sourceFile << "const char* const passwords[] ="     << std::endl;
        sourceFile << "{"                                   << std::endl;
        for (std::vector<std::string>::const_iterator i = this->passwords.begin(); i != this->passwords.end(); ++i)
        {
            std::vector<char> mutablePassword(i->c_str(), i->c_str() + i->size() + 1);
            char* password = &mutablePassword[0];
            rot13(password);

            sourceFile << "    \"" << password << "\"";

            if (i+1 != this->passwords.end())
            {
                sourceFile << ",";
            }
            sourceFile << std::endl;
        }
        sourceFile << "};"                                  << std::endl;
        sourceFile << ""                                    << std::endl;
        sourceFile << "const char* const flags[] ="         << std::endl;
        sourceFile << "{"                                   << std::endl;
        for (std::vector<std::string>::const_iterator i = this->flags.begin(); i != this->flags.end(); ++i)
        {
            std::vector<char> mutableFlag(i->c_str(), i->c_str() + i->size() + 1);
            char* flag = &mutableFlag[0];
            rot13(flag);

            sourceFile << "    \"" << flag << "\"";
            if (i+1 != this->flags.end())
            {
                sourceFile << ",";
            }
            sourceFile << std::endl;
        }
        sourceFile << "};"                                  << std::endl;

        if (sourceFile.fail() || sourceFile.bad())
        {
            throw std::runtime_error("Cannot create source file.");
        }
    }
};

int main(int argc, char* argv[])
{
    try
    {
        if (argc < 2)
        {
            throw std::runtime_error("Insufficient parameters.");
        }
        
        ChaffGenerator chaffGen(argv[1]);
        chaffGen.generateChaff();
        chaffGen.generateSource();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}
