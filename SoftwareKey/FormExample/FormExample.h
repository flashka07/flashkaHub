
// FormExample.h : главный файл заголовка для приложения PROJECT_NAME
//

#pragma once

#ifndef __AFXWIN_H__
	#error "включить stdafx.h до включения этого файла в PCH"
#endif

#include "resource.h"		// основные символы


// TFormExampleApp:
// О реализации данного класса см. FormExample.cpp
//

class TFormExampleApp : public CWinApp
{
public:
	TFormExampleApp();

// Переопределение
public:
	virtual BOOL InitInstance();

// Реализация

	DECLARE_MESSAGE_MAP()
};

extern TFormExampleApp theApp;