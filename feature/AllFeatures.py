import numpy as np
class global_info():
    def __init__(self,**kwargs):
        self.authorinfo={}
        for attr,val in kwargs.items():
            self.authorinfo[attr]=val
    def calaulateUsage(self):
        newUsageRate=self.authorinfo['newUsageNumber'] / (self.authorinfo['newUsageNumber'] +  self.authorinfo['oldUsageNumber']) if self.authorinfo['newUsageNumber'] + self.authorinfo['oldUsageNumber'] != 0 else None
        safeteUsageRate=self.authorinfo['safetyUsageNumber']/(self.authorinfo['safetyUsageNumber']+self.authorinfo['unsafetyUsageNumber']) if self.authorinfo['safetyUsageNumber']+self.authorinfo['unsafetyUsageNumber'] else None
        return newUsageRate,safeteUsageRate
#注释比率
    def calculateCommentRate(self):
        if self.authorinfo['codeLength']==0:
            return None
        return self.authorinfo['commentNumber'] / self.authorinfo['codeLength']
# 计算长函数所占比率，如果长度大于五十就算长函数
    def calculateLongFunctionRate(self):
        if self.authorinfo['functionNumber']==0:
            return None
        return self.authorinfo['longFunctionNumber']/ self.authorinfo['functionNumber']
#变量定义的位置
    def calculateVariableLocationVariance(self):
        if self.authorinfo['llen']==0:
            return 0
        return self.authorinfo['variableVariance']/self.authorinfo['llen']
#变量命名词汇
    def analyseEnglishLevel(self):
        if self.authorinfo['englishUsageTime']==0:
            return 0
        return self.authorinfo['englishScore'] / self.authorinfo['englishUsageTime']
    def extractmacro(self,code):
        if self.authorinfo['macroNumber']==0:
            return None
        return self.authorinfo['macroNumber']/self.authorinfo['identifier']
    def calculateEnglishLevelAndNormalNamingRate(self):
        identifierList = self.authorinfo['identifierNumber']
        if identifierList == 0:
            return 0, 0
        englishLevel = self.analyseEnglishLevel()

        return englishLevel, self.authorinfo['normalNumber'] / identifierList
    # 匿名函数
    def calculateLambdaFunctionNumber(self):
        if self.authorinfo['lambdaNumber'] + self.authorinfo['PointerFunc']+self.authorinfo['functionNumber'] == 0:
            return None
        return self.authorinfo['lambdaNumber'] / (self.authorinfo['lambdaNumber'] + self.authorinfo['PointerFunc']+self.authorinfo['functionNumber'])
    #异常,这里没有做改变，因为C++的异常处理都挺细致的
    def calculateIninlineFunctionNumber(self):
        if self.authorinfo['lambdaNumber'] + self.authorinfo['lambdaNumber'] + self.authorinfo['functionNumber'] == 0:
            return None
        return self.authorinfo['inlineNumber'] / (self.authorinfo['lambdaNumber'] + self.authorinfo['PointerFunc']+self.authorinfo['functionNumber'])
    def calculateVirtualFunctionNumber(self):
        if self.authorinfo['lambdaNumber'] + self.authorinfo['lambdaNumber'] + self.authorinfo['functionNumber'] == 0:
            return None
        return self.authorinfo['virtualNumber'] / (self.authorinfo['lambdaNumber'] + self.authorinfo['PointerFunc']+self.authorinfo['functionNumber'])
    def calculateTemplateFunctionNumber(self):
        if self.authorinfo['lambdaNumber'] + self.authorinfo['lambdaNumber']+self.authorinfo['functionNumber'] == 0:
            return None
        return self.authorinfo['TemplateNumber'] / (self.authorinfo['lambdaNumber'] + self.authorinfo['PointerFunc']+self.authorinfo['functionNumber'])
    def calculateStaticFunctionNumber(self):
        if self.authorinfo['lambdaNumber'] + self.authorinfo['lambdaNumber'] + self.authorinfo['functionNumber'] == 0:
            return None
        return self.authorinfo['staticNumber'] / (self.authorinfo['lambdaNumber'] + self.authorinfo['PointerFunc']+self.authorinfo['functionNumber'])
    def calculateExternFunctionNumber(self):
        if self.authorinfo['lambdaNumber'] + self.authorinfo['lambdaNumber'] + self.authorinfo['functionNumber'] == 0:
            return None
        return self.authorinfo['ExternNumber'] / (self.authorinfo['lambdaNumber'] + self.authorinfo['PointerFunc']+self.authorinfo['functionNumber'])
    def calculatePointerFunctionNumber(self):
        if self.authorinfo['lambdaNumber'] + self.authorinfo['lambdaNumber'] + self.authorinfo['functionNumber'] == 0:
            return None
        return self.authorinfo['PointerFunc'] / (self.authorinfo['lambdaNumber'] + self.authorinfo['PointerFunc']+self.authorinfo['functionNumber'])
    def calculatePointerVariable(self):
        if self.authorinfo['identifierNumber']==0:
            return None
        return self.authorinfo['PointerVar']/self.authorinfo['identifierNumber']
    def calculateMemoryRecall(self):
        if self.authorinfo['newNumber']==0:
            return None
        return self.authorinfo['deleteNumber']/self.authorinfo['newNumber']
    def macroIdentifier(self):
        if self.authorinfo['macroNumber']+self.authorinfo['identifierNumber']==0:
            return None
        return self.authorinfo['macroNumber']/(self.authorinfo['macroNumber']+self.authorinfo['identifierNumber'])
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

    def parse(self):
        newUsageRate, safetyUsageRate = self.calaulateUsage()
        commentRate = self.calculateCommentRate()
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
        print(normalNamingRate,localVariableVarience)
        neuroticism = self.calculateNeuroticism(normalNamingRate, localVariableVarience)#情绪

        return openness, conscientiousness, extroversion, agreeableness, neuroticism