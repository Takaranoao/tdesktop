/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "storage/storage_tdata_import.h"

#include "storage/details/storage_file_utilities.h"
#include "storage/details/storage_settings_scheme.h"
#include "storage/serialize_common.h"

#include "base/flat_set.h"

namespace Storage {
namespace {

using namespace Storage::details;

// 32 bytes — same value as LocalEncryptSaltSize in config.h (via PCH),
// kept as a local alias for clarity in this translation unit.
constexpr auto kLocalEncryptSaltSize = 32;

// Aligned with Main::Domain::kPremiumMaxAccounts (main_domain.h).
// Duplicated here to avoid including the heavyweight main_domain.h header.
constexpr auto kPremiumMaxAccounts = 99;

// Local copy of storage_account.cpp:116-124 (anonymous namespace — not
// externally callable).  We drop the legacy testAddition branch (same as the
// original: it was commented-out there too).
[[nodiscard]] FileKey ComputeDataNameKey(const QString &dataName) {
	const auto dataNameUtf8 = dataName.toUtf8();
	FileKey dataNameHash[2] = { 0 };
	hashMd5(dataNameUtf8.constData(), dataNameUtf8.size(), dataNameHash);
	return dataNameHash[0];
}

// Local copy of main_account.cpp:36-43 (anonymous namespace in Main).
[[nodiscard]] QString ComposeDataString(const QString &dataName, int index) {
	auto result = dataName;
	result.replace('#', QString());
	if (index > 0) {
		result += '#' + QString::number(index + 1);
	}
	return result;
}

// Parse userId from the blob produced by
// Main::Account::serializeMtpAuthorization() (see main_account.cpp:273-328).
// Format: [quint64 kWideIdsTag][quint64 userId][qint32 mainDcId]...
// Legacy fallback: [qint32 legacyUserId][qint32 mainDcId]...
[[nodiscard]] uint64 ReadUserIdFromBlob(const QByteArray &serialized) {
	constexpr auto kWideIdsTag = ~uint64(0);
	QDataStream stream(serialized);
	stream.setVersion(QDataStream::Qt_5_1);
	const auto legacyUserId = Serialize::read<qint32>(stream);
	const auto legacyMainDcId = Serialize::read<qint32>(stream);
	if (stream.status() != QDataStream::Ok) {
		return 0;
	}
	if (((uint64(legacyUserId) << 32) | uint64(legacyMainDcId))
		== kWideIdsTag) {
		const auto userId = Serialize::read<quint64>(stream);
		return (stream.status() == QDataStream::Ok) ? userId : uint64(0);
	}
	return uint64(legacyUserId); // legacy 32-bit userId
}

void ExtractAccounts(
		const QString &basePath,
		const QString &dataName,
		const MTP::AuthKeyPtr &srcLocalKey,
		const std::vector<int> &indices,
		TdataImportResult &result) {
	for (const auto index : indices) {
		// Each account's mtp file is keyed by its account-specific dataName.
		// Storage::Account stores it as:
		//   FileWriteDescriptor mtp(ToFilePart(_dataNameKey), BaseGlobalPath())
		// where _dataNameKey = ComputeDataNameKey(ComposeDataString(dataName, index)).
		const auto accountDataName = ComposeDataString(dataName, index);
		const auto dataNameKey    = ComputeDataNameKey(accountDataName);

		FileReadDescriptor mtp;
		// Use the string-name overload matching readMtpData in storage_account.cpp:1163.
		if (!ReadEncryptedFile(
				mtp,
				ToFilePart(dataNameKey),
				basePath,
				srcLocalKey)) {
			continue; // Missing or corrupt account file — skip (invariant 6).
		}
		while (!mtp.stream.atEnd()) {
			quint32 blockId = 0;
			mtp.stream >> blockId;
			if (!CheckStreamStatus(mtp.stream)) {
				break;
			}
			if (blockId == quint32(dbiMtpAuthorization)) {
				auto serialized = QByteArray();
				mtp.stream >> serialized;
				if (!CheckStreamStatus(mtp.stream)) {
					break;
				}
				result.accounts.push_back(ImportedAccount{
					.mtpAuthorization = serialized,
					.userId = ReadUserIdFromBlob(serialized),
				});
				break; // Only one dbiMtpAuthorization block per file.
			} else {
				// Unknown block — stop; we only need the auth blob.
				break;
			}
		}
	}
}

} // namespace

TdataImportResult ReadTdataAccounts(
		const QString &srcTdataDir,
		const QByteArray &passcode) {
	auto result = TdataImportResult();

	const auto basePath = QDir(srcTdataDir).absolutePath() + '/';
	const auto dataName = u"data"_q;

	// --- Step 1: read the key file ("key_data") ---
	FileReadDescriptor keyData;
	if (!ReadFile(keyData, "key_" + dataName, basePath)) {
		result.error = TdataImportError::NotATdataFolder;
		return result;
	}

	QByteArray salt, keyEncrypted, infoEncrypted;
	keyData.stream >> salt >> keyEncrypted >> infoEncrypted;
	if (!CheckStreamStatus(keyData.stream)
		|| salt.size() != kLocalEncryptSaltSize) {
		result.error = TdataImportError::Corrupted;
		return result;
	}

	// --- Step 2: derive passcode key and decrypt the local key ---
	const auto passcodeKey = CreateLocalKey(passcode, salt);
	EncryptedDescriptor keyInnerData;
	if (!DecryptLocal(keyInnerData, keyEncrypted, passcodeKey)) {
		result.error = passcode.isEmpty()
			? TdataImportError::NeedPasscode
			: TdataImportError::WrongPasscode;
		return result;
	}
	const auto key = Serialize::read<MTP::AuthKey::Data>(keyInnerData.stream);
	if (keyInnerData.stream.status() != QDataStream::Ok
		|| !keyInnerData.stream.atEnd()) {
		result.error = TdataImportError::Corrupted;
		return result;
	}
	const auto srcLocalKey = std::make_shared<MTP::AuthKey>(key);

	// --- Step 3: decrypt the accounts-index blob ---
	EncryptedDescriptor info;
	if (!DecryptLocal(info, infoEncrypted, srcLocalKey)) {
		result.error = TdataImportError::Corrupted;
		return result;
	}
	auto count = qint32();
	info.stream >> count;
	if (count <= 0 || count > kPremiumMaxAccounts) {
		result.error = TdataImportError::Corrupted;
		return result;
	}
	auto indices = std::vector<int>();
	indices.reserve(count);
	// Mirror startModern's `tried` set (storage_domain.cpp:170-178): an index
	// may appear more than once — only read each account's mtp file once.
	auto tried = base::flat_set<int>();
	for (auto i = 0; i != count; ++i) {
		auto index = qint32();
		info.stream >> index;
		if (info.stream.status() != QDataStream::Ok) {
			result.error = TdataImportError::Corrupted;
			return result;
		}
		if (index >= 0
			&& index < kPremiumMaxAccounts
			&& tried.emplace(index).second) {
			indices.push_back(index);
		}
	}

	// --- Step 4: read dbiMtpAuthorization from each account's mtp file ---
	ExtractAccounts(basePath, dataName, srcLocalKey, indices, result);
	return result;
}

} // namespace Storage
