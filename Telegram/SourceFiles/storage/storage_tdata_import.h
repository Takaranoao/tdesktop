/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/mtproto_dc_options.h" // MTP::DcId

namespace Storage {

// 单个从源 tdata 解析出的账号:mtpAuthorization 是
// Main::Account::serializeMtpAuthorization() 格式的 blob,
// 可直接喂给 Main::Account::setMtpAuthorization()。
struct ImportedAccount {
	QByteArray mtpAuthorization;
	uint64 userId = 0; // 用于去重 / 显示
};

enum class TdataImportError {
	None,
	NotATdataFolder, // 找不到 key_data
	NeedPasscode,    // 加密且未提供密码
	WrongPasscode,   // 密码错误
	Corrupted,       // 解析失败
};

struct TdataImportResult {
	TdataImportError error = TdataImportError::None;
	std::vector<ImportedAccount> accounts;
};

// 只读解析 srcTdataDir(指向某个 .../tdata 目录),不依赖全局 cWorkingDir。
// passcode 为空表示尝试无密码;若源加密则返回 NeedPasscode / WrongPasscode。
[[nodiscard]] TdataImportResult ReadTdataAccounts(
	const QString &srcTdataDir,
	const QByteArray &passcode);

} // namespace Storage
