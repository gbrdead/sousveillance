#include "rot13.h"

#include <random>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cctype>
#include <cstring>


const std::string FAKE_PASSWORD("BigBrotherIsWatchingYou");
const std::string REAL_PASSWORD("AlwaysDoubleCheck");
const std::string FAKE_FLAG("MuchDebuggerSoStaticAnalisysWow");
const std::string REAL_FLAG("VerySuspicionManyInquiryWow");

const unsigned CHAFF_SIZE = 100;


class ChaffGenerator
{
private:
    std::random_device randomDev;

    unsigned realPasswordIndex;
    unsigned realFlagIndex;
    unsigned fakePasswordIndex;
    unsigned fakeFlagIndex;

public:
    ChaffGenerator()
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
    }

    void generateSource()
    {
        this->generateHeader();
        this->generateSourceFile();
    }

private:
    void generateHeader()
    {
        std::ofstream headerFile("chaff.h");

        headerFile << "#ifndef __CTF_PTOOIE_CHAFF_H__"                              << std::endl;
        headerFile << "#define __CTF_PTOOIE_CHAFF_H__"                              << std::endl;
        headerFile << ""                                                            << std::endl;
        headerFile << "#include \"rot13.h\""                                        << std::endl;
        headerFile << ""                                                            << std::endl;
        headerFile << ""                                                            << std::endl;
        headerFile << "#ifdef __cplusplus"                                          << std::endl;
        headerFile << "extern \"C\""                                                << std::endl;
        headerFile << "{"                                                           << std::endl;
        headerFile << "#endif"                                                      << std::endl;
        headerFile << ""                                                            << std::endl;
        headerFile << "extern const struct EncryptedString const passwords[];"      << std::endl;
        headerFile << "extern const struct EncryptedString const flags[];"          << std::endl;
        headerFile << ""                                                            << std::endl;
        headerFile << "#ifdef __cplusplus"                                          << std::endl;
        headerFile << "}"                                                           << std::endl;
        headerFile << "#endif"                                                      << std::endl;
        headerFile << ""                                                            << std::endl;
        headerFile << ""                                                            << std::endl;
        headerFile << "#define REAL_PASSWORD_INDEX " << this->realPasswordIndex     << std::endl;
        headerFile << "#define REAL_FLAG_INDEX " << this->realFlagIndex             << std::endl;
        headerFile << "#define FAKE_PASSWORD_INDEX " << this->fakePasswordIndex     << std::endl;
        headerFile << "#define FAKE_FLAG_INDEX " << this->fakeFlagIndex             << std::endl;
        headerFile << ""                                                            << std::endl;
        headerFile << ""                                                            << std::endl;
        headerFile << "#endif"                                                      << std::endl;

        if (headerFile.fail() || headerFile.bad())
        {
            throw std::runtime_error("Cannot create header file.");
        }
    }

    void generateSourceFile()
    {
        std::ofstream sourceFile("chaff.c");

        sourceFile << "#include \"chaff.h\""                                        << std::endl;
        sourceFile << ""                                                            << std::endl;
        sourceFile << ""                                                            << std::endl;
        this->generatePasswordsOrFlags(sourceFile, "passwords", this->realPasswordIndex, this->fakePasswordIndex, REAL_PASSWORD, FAKE_PASSWORD);
        sourceFile << ""                                                            << std::endl;
        this->generatePasswordsOrFlags(sourceFile, "flags", this->realFlagIndex, this->fakeFlagIndex, REAL_FLAG, FAKE_FLAG);

        if (sourceFile.fail() || sourceFile.bad())
        {
            throw std::runtime_error("Cannot create source file.");
        }
    }

    void generatePasswordsOrFlags(std::ostream& sourceFile, const std::string& varName, unsigned realIndex, unsigned fakeIndex, const std::string& real, const std::string& fake)
    {
        sourceFile << "const struct EncryptedString const " << varName << "[] ="    << std::endl;
        sourceFile << "{"                                                           << std::endl;
        for (unsigned i = 0; i < CHAFF_SIZE; i++)
        {
            EncryptedString encStr;

            if (i != realIndex && i != fakeIndex)
            {
                this->fillRandomEncryptedString(encStr);
            }
            else
            {
                const std::string& str = (i == realIndex) ? real : fake;
                this->encryptString(encStr, str);
            }
            sourceFile << "    {0x" << std::hex << encStr.prngSeed << ", ";
            sourceFile << std::dec << "{";
            for (unsigned j = 0; j < ENCRYPTED_STRING_MAX_SIZE; j++)
            {
                sourceFile << (int)encStr.str[j];
                if (j < ENCRYPTED_STRING_MAX_SIZE-1)
                {
                    sourceFile << ", ";
                }
            }
            sourceFile << "}}";

            if (i+1 != CHAFF_SIZE)
            {
                sourceFile << ", ";
            }
            sourceFile << std::endl;
        }
        sourceFile << "};"                                                          << std::endl;
    }

    void encryptString(EncryptedString& encStr, const std::string& unencryptedStr)
    {
        this->initializeRandomSeed(encStr);
        std::strncpy(encStr.str, unencryptedStr.c_str(), ENCRYPTED_STRING_MAX_SIZE * sizeof(char));

        uint64_t prngState = encStr.prngSeed;
        for (char* c = encStr.str; c < encStr.str + ENCRYPTED_STRING_MAX_SIZE; c++)
        {
            char randomValue = xorshift64star(&prngState);
            *c +=  randomValue;
        }
    }

    void fillRandomEncryptedString(EncryptedString& encStr)
    {
        this->initializeRandomSeed(encStr);

        for (char* c = encStr.str; c < encStr.str + ENCRYPTED_STRING_MAX_SIZE; c++)
        {
            *c = this->randomDev();
        }
    }

    void initializeRandomSeed(EncryptedString& encStr)
    {
        encStr.prngSeed = ((uint64_t)this->randomDev() << 32) | this->randomDev();
    }
};

int main(int argc, char* argv[])
{
    try
    {
        ChaffGenerator chaffGen;
        chaffGen.generateSource();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}
