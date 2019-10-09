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

#ifndef KEEPASSXC_TESTLEVENSHTEIN_H
#define KEEPASSXC_TESTLEVENSHTEIN_H

#include <QObject>
#include <QSharedPointer>

#include "core/Database.h"

class TestLevenshtein : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void init();
    void testEqualStrings();
    void testAdditionOfCharactersOnly();
    void testRemovalOfCharactersOnly();
    void testSubstitutionOfCharactersOnly();
    void testAdditionAndSubstitutionOfCharacters();
    void testRemovalAndSubstitutionOfCharacters();
    void testAdditionAndRemovalAndSubstitutionOfCharacters();

private:
    QSharedPointer<Database> m_db;
};

#endif // KEEPASSXC_TESTLEVENSHTEIN_H
