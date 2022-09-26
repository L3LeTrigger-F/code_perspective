from .CPP14ParserListener import CPP14ParserListener
from .CPP14Parser import CPP14Parser
from antlr4 import *

class CPP14Extract(CPP14ParserListener):
    def __init__(self):
        super().__init__()
        # function-based
        self.functionNumber = 0
        self.functionList = []
        self.lambdaFunctionNumber = 0
        # class-based
        self.classNameList = []
        self.classNumber = 0
        self.classVariableNameList = []
        self.classVariableNumber = 0
        self.identifierList=[]
        self.identifierNumber=0
        # quote 引用
        self.importNumber = 0
        self.importNameList = []
        # code style
        self.exceptionNumber = 0
        self.exceptionNameList = []
        self.packageNumber = 0
        self.packageNameList = []
    #需要function_number classname_list classvaribale_list
    def enterClassName(self, ctx:CPP14Parser.ClassNameContext):
        self.classNameList.append(ctx.getText())
        self.classNumber += 1
        return super().enterClassName(ctx)
    def enterFunctionDefinition(self, ctx:CPP14Parser.FunctionDefinitionContext):
        # capture function information
        #functionName = ctx.functionBody().
        functionBody = ctx.getText()
        functionStartLine = ctx.start.line
        functionEndLine = ctx.stop.line
        self.functionList.append(
            {
                #'functionName': functionName,
                'functionBody': functionBody,
                'functionStartLine': functionStartLine,
                'functionEndLine': functionEndLine,
                'localVariableList': [],
                'functionCallList': []
            }
        )
        self.functionNumber += 1
        return super().enterFunctionDefinition(ctx)

    def enterIdExpression(self, ctx:CPP14Parser.IdExpressionContext):
        identifiername=ctx.getText()
        self.identifierList.append(identifiername)
        self.identifierNumber+=1
        return super().enterIdExpression(ctx)
    #定义在函数外怎么办？
    def enterFunctionSpecifier(self, ctx:CPP14Parser.FunctionSpecifierContext):
        functionCallName = ctx.getText()
        functionCallLine = ctx.start.line
        functionCallColumn = ctx.start.column

        if len(self.functionList) != 0:
            if functionCallLine >= self.functionList[-1]['functionStartLine'] \
                    and functionCallLine <= self.functionList[-1]['functionEndLine']:
                self.functionList[-1]['functionCallList'].append(
                    {
                        'functionCallName': functionCallName,
                        'line': functionCallLine,
                        'column': functionCallColumn
                    }
                )
        return super().enterFunctionSpecifier(ctx)
    def enterDeclarator(self, ctx:CPP14Parser.DeclaratorContext):
        variableList=ctx.getText()
        variableLine = ctx.start.line
        variableColumn = ctx.start.column
        if self.functionList!=[]:
            self.functionList[-1]['localVariableList'].append(
                {
                    'variableName': variableList,
                    'Line': variableLine,
                    'Column': variableColumn
                }
            )
        return super().enterDeclarator(ctx)
    def enterLambdaExpression(self, ctx:CPP14Parser.LambdaExpressionContext):
        self.lambdaFunctionNumber+=1
        return super().enterLambdaExpression(ctx)
    def enterExceptionDeclaration(self, ctx:CPP14Parser.ExceptionDeclarationContext):
        exceptionName=ctx.getText()
        self.exceptionNameList.append(exceptionName)
        self.exceptionNumber += 1
        return super().enterExceptionDeclaration(ctx)

