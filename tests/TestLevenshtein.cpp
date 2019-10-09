/*
 *  Copyright (C) 2019 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "TestLevenshtein.h"

#include "config-keepassx-tests.h"

#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "core/Levenshtein.h"
#include "crypto/Crypto.h"

#include <QBuffer>
#include <QByteArray>
#include <QFile>
#include <QList>
#include <QTest>

QTEST_GUILESS_MAIN(TestLevenshtein)

void TestLevenshtein::init()
{
    m_db.reset(new Database());
}

void TestLevenshtein::initTestCase()
{
    QVERIFY(Crypto::init());
}

/**
 * Two equal strings should have a Levenshtein distance of 0.
 */
void TestLevenshtein::testEqualStrings()
{
    QCOMPARE(Levenshtein::distance("", ""), 0);
    QCOMPARE(Levenshtein::distance("bad-password", "bad-password"), 0);
    QCOMPARE(Levenshtein::distance("KDSGe7C4zXeCDaeJk2", "KDSGe7C4zXeCDaeJk2"), 0);
    QCOMPARE(Levenshtein::distance("#:qWgKYxgHM)g#'G=7-z!,MS", "#:qWgKYxgHM)g#'G=7-z!,MS"), 0);
}

/**
 * Two strings that differ only by adding characters should have a Levenshtein
 * distance equal to the number of additional characters.
 */
void TestLevenshtein::testAdditionOfCharactersOnly()
{
    QCOMPARE(Levenshtein::distance("", "p"), 1);
    QCOMPARE(Levenshtein::distance("", "pass"), 4);
    QCOMPARE(Levenshtein::distance("", "password"), 8);
    QCOMPARE(Levenshtein::distance("password", "password1"), 1);
    QCOMPARE(Levenshtein::distance("password", "password2019"), 4);
    QCOMPARE(Levenshtein::distance("password", "1password"), 1);
    QCOMPARE(Levenshtein::distance("password", "2019password"), 4);
    QCOMPARE(Levenshtein::distance("password", "1password1"), 2);
    QCOMPARE(Levenshtein::distance("password", "1password2019"), 5);
    QCOMPARE(Levenshtein::distance("password", "2019password1"), 5);
    QCOMPARE(Levenshtein::distance("password", "2019password2019"), 8);
    QCOMPARE(Levenshtein::distance("password", "pass1word"), 1);
    QCOMPARE(Levenshtein::distance("password", "pass2019word"), 4);
    QCOMPARE(Levenshtein::distance("password", "p-a-s-s-w-o-r-d"), 7);
}

/**
 * Two strings that differ only by removing characters should have a Levenshtein
 * distance equal to the number of removed characters.
 */
void TestLevenshtein::testRemovalOfCharactersOnly()
{
    QCOMPARE(Levenshtein::distance("password", ""), 8);
    QCOMPARE(Levenshtein::distance("pass", ""), 4);
    QCOMPARE(Levenshtein::distance("p", ""), 1);
    QCOMPARE(Levenshtein::distance("password1", "password"), 1);
    QCOMPARE(Levenshtein::distance("password2019", "password"), 4);
    QCOMPARE(Levenshtein::distance("1password", "password"), 1);
    QCOMPARE(Levenshtein::distance("2019password", "password"), 4);
    QCOMPARE(Levenshtein::distance("1password1", "password"), 2);
    QCOMPARE(Levenshtein::distance("1password2019", "password"), 5);
    QCOMPARE(Levenshtein::distance("2019password1", "password"), 5);
    QCOMPARE(Levenshtein::distance("2019password2019", "password"), 8);
    QCOMPARE(Levenshtein::distance("pass1word", "password"), 1);
    QCOMPARE(Levenshtein::distance("pass2019word", "password"), 4);
    QCOMPARE(Levenshtein::distance("p-a-s-s-w-o-r-d", "password"), 7);
}

/**
 * Two strings that differ only by substituting characters should have a
 * Levenshtein distance equal to the number of substituted characters.
 */
void TestLevenshtein::testSubstitutionOfCharactersOnly()
{
    QCOMPARE(Levenshtein::distance("password", "1assword"), 1);
    QCOMPARE(Levenshtein::distance("password", "12ssword"), 2);
    QCOMPARE(Levenshtein::distance("password", "123sword"), 3);
    QCOMPARE(Levenshtein::distance("password", "1234word"), 4);
    QCOMPARE(Levenshtein::distance("password", "12345ord"), 5);
    QCOMPARE(Levenshtein::distance("password", "123456rd"), 6);
    QCOMPARE(Levenshtein::distance("password", "1234567d"), 7);
    QCOMPARE(Levenshtein::distance("password", "12345678"), 8);
    QCOMPARE(Levenshtein::distance("password", "p2345678"), 7);
    QCOMPARE(Levenshtein::distance("password", "pa345678"), 6);
    QCOMPARE(Levenshtein::distance("password", "pas45678"), 5);
    QCOMPARE(Levenshtein::distance("password", "pass5678"), 4);
    QCOMPARE(Levenshtein::distance("password", "passw678"), 3);
    QCOMPARE(Levenshtein::distance("password", "passwo78"), 2);
    QCOMPARE(Levenshtein::distance("password", "passwor8"), 1);
    QCOMPARE(Levenshtein::distance("password", "pXssword"), 1);
    QCOMPARE(Levenshtein::distance("password", "paXsword"), 1);
    QCOMPARE(Levenshtein::distance("password", "pasXword"), 1);
    QCOMPARE(Levenshtein::distance("password", "passXord"), 1);
    QCOMPARE(Levenshtein::distance("password", "passwXrd"), 1);
    QCOMPARE(Levenshtein::distance("password", "passwoXd"), 1);
    QCOMPARE(Levenshtein::distance("password", "pXsXword"), 2);
    QCOMPARE(Levenshtein::distance("password", "paXsXord"), 2);
    QCOMPARE(Levenshtein::distance("password", "pasXwXrd"), 2);
    QCOMPARE(Levenshtein::distance("password", "passXoXd"), 2);
}

/**
 * Two strings that differ by adding and substituting characters should have a
 * Levenshtein distance equal to the number of additional characters plus the
 * number of substituted characters.
 */
void TestLevenshtein::testAdditionAndSubstitutionOfCharacters()
{
    QCOMPARE(Levenshtein::distance("password", "XXassword"), 2);
    QCOMPARE(Levenshtein::distance("password", "XXXXssword"), 4);
    QCOMPARE(Levenshtein::distance("password", "passworXX"), 2);
    QCOMPARE(Levenshtein::distance("password", "passwoXXXX"), 4);
    QCOMPARE(Levenshtein::distance("password", "XpassworX"), 2);
    QCOMPARE(Levenshtein::distance("password", "XXpasswoXX"), 4);
    QCOMPARE(Levenshtein::distance("password", "XasswordX"), 2);
    QCOMPARE(Levenshtein::distance("password", "XXsswordXX"), 4);
    QCOMPARE(Levenshtein::distance("password", "XpaXswXrdX"), 4);
}

/**
 * Two strings that differ by removing and substituting characters should have a
 * Levenshtein distance equal to the number of removed characters plus the
 * number of substituted characters.
 */
void TestLevenshtein::testRemovalAndSubstitutionOfCharacters()
{
    QCOMPARE(Levenshtein::distance("password", "assworX"), 2);
    QCOMPARE(Levenshtein::distance("password", "sswoXX"), 4);
    QCOMPARE(Levenshtein::distance("password", "swXXX"), 6);
    QCOMPARE(Levenshtein::distance("password", "XXXX"), 8);
    QCOMPARE(Levenshtein::distance("password", "Xasswor"), 2);
    QCOMPARE(Levenshtein::distance("password", "XXsswo"), 4);
    QCOMPARE(Levenshtein::distance("password", "XXXsw"), 6);
}

/**
 * Two strings that differ by adding, removing and substituting characters
 * should have a Levenshtein distance equal to the number of additional
 * characters plus the removed characters plus the number of substituted
 * characters.
 */
void TestLevenshtein::testAdditionAndRemovalAndSubstitutionOfCharacters()
{
    // Add 1, substitute 2, remove 1 = 4
    QCOMPARE(Levenshtein::distance("password", "XpasXXor"), 4);
    // Add 2, substitute 4, remove 2 = 8
    QCOMPARE(Levenshtein::distance("password", "XXpaXXXX"), 8);
}
