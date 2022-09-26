import json
import re
import numpy as np
import time
from antlr4 import *
from src.spam.parser.CPPExtract import CPP14Extract
from src.spam.parser.sa_cpp14 import *
import spam
class ExampleErrorListener(SA_ErrorListener):
    def syntaxError(self, input_stream, offendingSymbol,
        char_index:int, line:int, column:int, msg:str
    ):
        print("Syntax Error!")
        print("    input_stream:", repr(input_stream))
        print("    offendingSymbol:", offendingSymbol, type(offendingSymbol))
        print("    char_index:", char_index)
        print("    line:", line)
        print("    column:", column)
        print("    msg:", msg)
class FileParser():
    def __init__(self):
        self.listener = CPP14Extract()
        self.walker = ParseTreeWalker()
        self.authorinfo = {
            'newUsageNumber': 0,
            'oldUsageNumber': 0,
            'safetyUsageNumber': 0,
            'unsafetyUsageNumber': 0,
            'externFunctionNumber': 0,
            'commentNumber': 0,
            'codeLength': 0,
            'longFunctionNumber': 0,
            'functionNumber': 0,
            'variableVariance': 0,
            'englishScore': 0,
            'englishUsageTime': 0,
            'macroNumber': 0,
            'identifierNumber': 0,
            'lambdaNumber': 0,
            'inlineNumber': 0,
            'virtualNumber': 0,
            'TemplateNumber': 0,
            'staticNumber': 0,
            'ExternNumber': 0,
            'PointerFunc': 0,
            'PointerVar': 0,
            'normalNumber':0,
            'newNumber': 0,
            'deleteNumber': 0
        }
    def calaulateUsage(self, code):
        #以C++17为标准
        rules_new = [
            r"#include<Filesystem>",r"apply\([(.*?)]\)",r"invoke([(.*?)])",r"optional<[(.*?)]>",
            r"#include<any>",r"#include<variant>",r"#include<string_new>",r"scoped_lock",
            r"make_from_tuple",r"charconv",r"search\([(.*?)]\)",
            r"default_searcher",r"boyer_moore_searcher",r"boyer_moore_horspool_searcher",
            r"execution",r"memory_resource",r"if constexpr",r"u8'[(.*?)]'",r"[[fallthrough]]",
            r"[[nodiscard]]",r"[[maybe_unused]]",r"__has_include",r"static_assert([(.*?)]^,)",r"template<template<typename",
            r"namespace [(.*?)]::[(.*?)]::"
        ]
        # abandon usage
        rules_old = [
            r"std::auto_ptr",r"char *",r"register",r"unexpected_handler",r"set_unexpected()",r"convert_type",
            r"<ccomplex>",r"<cstdalign>",r"<cstdbool>",r"<ctgmath>",r"gets()",r"throw([(.*?)])",r"trigraph",r"static constexpr",
            r"random_shuffle",r"allocator<void>",r"<codecvt>",r"raw_storage_iterator",r"get_temporary_buffer",r"is_literal_type",
            r"std::iterator",r"memory_order_consume",r"shared_ptr::unique",r"result_of"
        ]
        # safety usage
        rules_safety = [
            r"fgets",r"gets_s",r"strncpy",r"strcpy_s",r"strncat",r"strcat_s",r"snprintf",r"_snprintf_s",
            r"_snwprintf_s",r"vsnprintf",r"strtol",r"strtoll",r"strtof",r"strtod",r"strncpy",r"strlcpy",r"strcpy_s",
            r"strncat",r"strlcat",r"strcat_s",r"strtok",r"snprintf",r"vsnprintf",r"_makepath_s",r"_splitpath_s",
            r"_splitpath_s",r"_snscanf_s",r"strnlen_s"
        ]
        rules_unsafety=[
            r"gets",r"strcpy",r"strcat",r"sprintf",r"scanf",r"sscanf",r"fscanf",r"vfscanf",r"vsprintf",r"vsscanf",
            r"stread",r"strecpy",r"strtrns",r"realpath",r"syslog",r"getopt",r"getopt_long",r"getpass",r"getchar",
            r"fgetc",r"getc",r"read",r"bcopy",r"memcpy",r"snprintf",r"strccpy",r"strcadd",r"atoi",r"atol",r"atoll",
            r"stof",r"strcpy",r"strcat",r"sprintf",r"vsprintf",r"makepath",r"_splitpath",r"scanf",r"sscanf",r"snscanf",
            r"strlen"
        ]
        new_list=[re.findall(rule, str(code)) for rule in rules_new]
        newUsageNumber = sum([len(re.findall(rule, str(code))) for rule in rules_new])
        oldUsageNumber = sum([len(re.findall(rule, str(code))) for rule in rules_old])
        safetyUsageNumber = sum([len(re.findall(rule, str(code))) for rule in rules_safety])
        unsafetyUsageNumber=sum([len(re.findall(rule, str(code))) for rule in rules_unsafety])
        newUsageRate=newUsageNumber / (newUsageNumber + oldUsageNumber) if newUsageNumber + oldUsageNumber != 0 else None
        safeteUsageRate=safetyUsageNumber/(safetyUsageNumber+unsafetyUsageNumber) if safetyUsageNumber+unsafetyUsageNumber!=0 else None
        self.authorinfo['newUsageNumber']+=newUsageNumber
        self.authorinfo['oldUsageNumber']+=oldUsageNumber
        self.authorinfo['safetyUsageNumber']+=safetyUsageNumber
        self.authorinfo['unsafetyUsageNumber']+=unsafetyUsageNumber
        return newUsageRate,safeteUsageRate
 #C++字符串形式更改，正则表达式 字符串夹杂变量是否考虑？
    def extractStringOutput(self, code):
        rules=[
        r'std::cout<<'
          r'cout<<"(.*?)"',
          r'printf[(]""(.*?)"(.*?)[)]',
          r'throw "(.*?)"',
          r'return "(.*?)"',
          r'cerr<<"(.*?)"'
        ]
        stringOutput = []
        for rule in rules:
            stringOutput.extend(re.findall(rule, code))
        return stringOutput
    def extractExternFunction(self,code):#正则匹配法
        extern_rules=r'extern(.*?)\((.*?)\)'
        self.listener.externFunctionNumber+=sum([len(re.findall(extern_rules, str(code)))])
        #self.authorinfo['externFunctionNumber']+=sum([len(re.findall(extern_rules, str(code)))])
    #提取注释
    def extractComment(self, tokenStream):#注释
        comment = []
        for token in tokenStream.tokens:
            if token.channel == 4:
                comment.append(token.text)

        return comment
#注释比率
    def calculateCommentRate(self, comment, file):
        codeLength =len(file)
        self.authorinfo['commentNumber']+=len(comment)
        self.authorinfo['codeLength']+=codeLength
        return len(comment) / codeLength
# 计算长函数所占比率，如果长度大于五十就算长函数
    def calculateLongFunctionRate(self):
        #how to define long function
        long_length=50
        if self.listener.functionNumber == 0:
            return None
        functionLength = []
        #print(self.listener.functionList['functionBody'])

        for function in self.listener.functionList:
            functionLength.append(function['functionEndLine'] - function['functionStartLine'] + 1)
        longFunctionNumber = sum(length > long_length for length in functionLength)
        self.authorinfo['longFunctionNumber']+=longFunctionNumber
        self.authorinfo['functionNumber']+=self.listener.functionNumber
        return longFunctionNumber / self.listener.functionNumber
#变量定义的位置
    def calculateVariableLocationVariance(self):
        if self.listener.functionNumber == 0:
            return None
        variableRelativeLocationAfterNorm = []
        for function in self.listener.functionList:
            functionLength = function['functionEndLine'] - function['functionStartLine'] + 1
            for variable in function['localVariableList']:
                variableRelativeLocationAfterNorm.append(
                    (variable['Line'] - function['functionStartLine'] + 1) / functionLength)
        variableVariance = np.std(variableRelativeLocationAfterNorm)
        self.authorinfo['variableVariance']+=variableVariance
        return variableVariance
#变量命名词汇
    def analyseEnglishLevel(self, wordList):
        if len(wordList) == 0:
            return None
        with open('./WordLevel.json') as fp:
            englishDict = json.load(fp)
        englishScore = 0
        englishUsageTime = 0
        for word in wordList:
            if word.isalpha() and word in englishDict:
                englishScore += englishDict[word]
                englishUsageTime += 1
        self.authorinfo['englishScore']+=englishScore
        self.authorinfo['englishUsageTime']+=englishUsageTime
        return englishScore / englishUsageTime if englishUsageTime != 0 else 0
    def extractmacro(self,code):
        macro_rules='#define (.*?)'
        self.listener.macroNumber = sum([len(re.findall(rule, str(code))) for rule in macro_rules])
        self.authorinfo['macroNumber']+=self.listener.macroNumber
        if self.listener.macroNumber==0:
            return None
        if self.listener.identifierNumber!=0:
            return self.listener.macroNumber/(self.listener.identifierNumber)
        return None
    def extractWordAndNamingConvention(self, identifier):
        '''
        Support Cammel and UnderScore Naming Convention

        Tip: When identifier is only a word, we assume its naming convention is UnderScore
        '''

        cammelPattern = re.compile('([a-z0-9]+|[A-Z][a-z0-9]+)((?:[A-Z0-9][a-z0-9]*)*)')
        result = cammelPattern.match(identifier)
        if result:
            wordList = []
            wordList.append(result.group(1))
            for word in re.findall('[A-Z0-9][a-z0-9]*', result.group(2)):
                wordList.append(word)
            return wordList, True

        underScorePattern = re.compile('[a-z0-9]+(_[a-z0-9]+)')
        if underScorePattern.match(identifier):
            wordList = identifier.split('_')
            return wordList, True

        return None, False

    def calculateEnglishLevelAndNormalNamingRate(self):
        identifierList = self.listener.identifierList
        if len(identifierList) == 0:
            return None, None

        normalIdentifierNumber = 0
        wordList = []
        for identifier in identifierList:
            wordFromIdentifier, isNormal = self.extractWordAndNamingConvention(identifier)
            if isNormal:
                wordList.extend(wordFromIdentifier)
                normalIdentifierNumber += 1
        englishLevel = self.analyseEnglishLevel(wordList)
        self.authorinfo['normalNumber']+=normalIdentifierNumber
        return englishLevel, normalIdentifierNumber / len(identifierList)
    # 匿名函数
    def calculateLambdaFunctionNumber(self):
        if self.listener.lambdaFunctionNumber + self.listener.functionNumber == 0:
            return None
        self.authorinfo['lambdaNumber']+=self.listener.lambdaFunctionNumber
        return self.listener.lambdaFunctionNumber / (self.listener.lambdaFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber)
    #异常,这里没有做改变，因为C++的异常处理都挺细致的
    def calculateIninlineFunctionNumber(self):
        if self.listener.lambdaFunctionNumber + self.listener.functionNumber == 0:
            return None
        self.authorinfo['inlineNumber'] += self.listener.inlineFunctionNumber
        return self.listener.inlineFunctionNumber / (self.listener.lambdaFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber)
    def calculateVirtualFunctionNumber(self):
        if self.listener.lambdaFunctionNumber+ self.listener.functionNumber == 0:
            return None
        self.authorinfo['virtualNumber'] += self.listener.virtualFunctionNumber
        return self.listener.virtualFunctionNumber / (self.listener.lambdaFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber)
    def calculateTemplateFunctionNumber(self):
        if self.listener.lambdaFunctionNumber+ self.listener.functionNumber == 0:
            return None
        self.authorinfo['TemplateNumber'] += self.listener.templateFunctionNumber
        return self.listener.templateFunctionNumber / (self.listener.lambdaFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber)
    def calculateStaticFunctionNumber(self):
        if self.listener.lambdaFunctionNumber + self.listener.functionNumber == 0:
            return None
        self.authorinfo['staticNumber'] += self.listener.staticFunctionNumber
        return self.listener.staticFunctionNumber / (self.listener.lambdaFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber)
    def calculateExternFunctionNumber(self):
        if self.listener.lambdaFunctionNumber + self.listener.functionNumber == 0:
            return None
        self.authorinfo['ExternNumber'] += self.listener.ExternFunctionNumber
        return self.listener.externFunctionNumber / (self.listener.lambdaFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber)
    def calculatePointerFunctionNumber(self):
        if self.listener.pointerFunctionNumber + self.listener.functionNumber == 0:
            return None
        self.authorinfo['PointerFunc'] += self.listener.pointerFunctionNumber
        return self.listener.pointerFunctionNumber / (self.listener.lambdaFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber)
    def calculatePointerVariable(self):
        if self.listener.identifierNumber==0:
            return None
        self.authorinfo['PointerVar']+=self.listener.pointervarNumber
        return self.listener.pointervarNumber/self.listener.identifierNumber
    def calculateMemoryRecall(self):
        if self.listener.newNumber==0:
            return None
        self.authorinfo['newNumber']+=self.listener.newNumber
        self.authorinfo['deleteNumber']+=self.listener.deleteNumber
        return self.listener.deleteNumber/self.listener.newNumber
    def macroIdentifier(self):
        if self.listener.macroNumber+self.listener.identifierNumber==0:
            return None
        self.authorinfo['macroNumber']+=self.listener.macroNumber
        return self.listener.macroNumber/(self.listener.macroNumber+self.listener.identifierNumber)
    def calculateOpenness(self, newUsageRate):
        return newUsageRate

    def calculateConscientiousness(self, safetyUsageRate, normalNamingRate,
                                   longFunctionRate, commentRate,memoryRecallRate,pointerFunctionRate,pointercallRate,virtualFunctionRate,inlineFunctionRate,
                                   macroFunctionRate):
        conscientiousness = []

        if safetyUsageRate != None:
            conscientiousness.append(safetyUsageRate)

        if normalNamingRate != None:
            conscientiousness.append(normalNamingRate)

        if longFunctionRate != None:
            conscientiousness.append(max((1 - 1.3 * longFunctionRate), 0))

        if commentRate != None:
            if commentRate < 1 / 3:
                conscientiousness.append(5 / 3 * commentRate)
            elif commentRate < 2:
                conscientiousness.append(0.5 + 0.25 * commentRate)
            else:
                conscientiousness.append(0.5 - 0.1 * commentRate)
        if virtualFunctionRate != None:
            conscientiousness.append(0.5 + 0.5 * virtualFunctionRate)
        if inlineFunctionRate != None:
            conscientiousness.append(0.5 + 0.5 * inlineFunctionRate)
        if pointerFunctionRate != None:
            conscientiousness.append(0.5 - 0.5 * pointerFunctionRate)
        if pointercallRate != None:
            conscientiousness.append(0.5 - 0.5 * pointercallRate)

        if memoryRecallRate != None:
            conscientiousness.append(memoryRecallRate)
        if macroFunctionRate != None:
            conscientiousness.append(0.5 + 0.5 * macroFunctionRate)
        return np.mean(conscientiousness)

    def calculateExtroversion(self, commentRate):#外倾性：注释
        extroversion = []

        if commentRate != None:
            if commentRate < 1 / 3:
                extroversion.append(5 / 3 * commentRate)
            elif commentRate < 2:
                extroversion.append(0.5 + 0.25 * commentRate)
            else:
                extroversion.append(0.5 - 0.1 * commentRate)

        return np.mean(extroversion)

    def calculateAgreeableness(self, newUsageRate, longFunctionRate,lambdaFunctionrate):#宜人性
        agreeableness = []
        if newUsageRate != None:
            if newUsageRate < 0.5:
                agreeableness.append(0.5 - 0.5 * newUsageRate)
            else:
                agreeableness.append(0.5 + 0.5 * newUsageRate)

        if longFunctionRate != None:
            agreeableness.append(max((1 - 1.3 * longFunctionRate), 0))

        if lambdaFunctionrate != None:
            agreeableness.append(1 - 0.5 * lambdaFunctionrate)


        return np.mean(agreeableness)

    def calculateNeuroticism(self, normalNamingRate, localVariableVarience):
        neuroticism = []

        if normalNamingRate != None:
            neuroticism.append(normalNamingRate)

        if localVariableVarience != None:
            neuroticism.append(1 - localVariableVarience)#为什么是1-

        return np.mean(neuroticism)

    def parse(self, filePath):
        print(filePath)
        #原先的生成树方式
        tokenStream = CommonTokenStream(CPP14Lexer(FileStream(filePath)))
        #parser = CPP14Parser(tokenStream)
        #预测模式
        #parser._interp.predictionMode = PredictionMode.SLL
        walker=ParseTreeWalker()
        stt=time.time()
        #spam是自行编译的包
        tree=spam.build_tree(filePath)
        print("time",time.time()-stt)
        start_time=time.time()
        self.walker.walk(self.listener, tree)
        #end_time=time.time()
        print("walk树时间：",time.time()-start_time)
        with open(filePath, 'r') as fp:
            fileData = fp.readlines()
        # extract code features
        start_time=time.time()
        self.authorinfo['identifierNumber']=self.listener.identifierNumber
        newUsageRate, safetyUsageRate = self.calaulateUsage(fileData)
        commentRate = self.calculateCommentRate(self.extractComment(tokenStream), fileData)
        longFunctionRate = self.calculateLongFunctionRate()
        localVariableVarience = self.calculateVariableLocationVariance()
        englishLevel, normalNamingRate = self.calculateEnglishLevelAndNormalNamingRate()
        pointerFunctionRate=self.calculatePointerFunctionNumber()
        pointercallRate=self.calculatePointerVariable()
        virtualFunctionRate=self.calculateVirtualFunctionNumber()
        inlineFunctionRate=self.calculateIninlineFunctionNumber()
        macroFunctionRate=self.macroIdentifier()
        memoryRecallRate=self.calculateMemoryRecall()
        lambdaFunctionRate=self.calculateLambdaFunctionNumber()
        # calculate psychological features
        openness = self.calculateOpenness(newUsageRate)#开放性
        conscientiousness = self.calculateConscientiousness(safetyUsageRate, normalNamingRate,
                                   longFunctionRate, commentRate,memoryRecallRate,pointerFunctionRate,pointercallRate,virtualFunctionRate,inlineFunctionRate,
                                   macroFunctionRate)#尽责性
        extroversion = self.calculateExtroversion(commentRate)#外倾性
        agreeableness = self.calculateAgreeableness(newUsageRate, longFunctionRate,lambdaFunctionRate)#宜人性
        neuroticism = self.calculateNeuroticism(normalNamingRate, localVariableVarience)#情绪
        print("计算时间：",time.time()-start_time)
        return self.authorinfo,openness, conscientiousness, extroversion, agreeableness, neuroticism

