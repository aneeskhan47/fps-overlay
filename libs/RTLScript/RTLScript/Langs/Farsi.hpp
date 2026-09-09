// RTLScript is a fork of FarsiType: https://github.com/AmyrAhmady/FarsiType

#pragma once

#include "Arabic.hpp"

namespace RTLScript::Farsi
{
	// ReSharper disable CommentTypo, IdentifierTypo
	enum class Tashkil : uint32_t {
		Fatheh              /**/ = Arabic::Tashkil::Fatha,
		TanvinNasb          /**/ = Arabic::Tashkil::Fathatan,
		TashkeelZammeh      /**/ = Arabic::Tashkil::Damma,
		TashkeelTanvinRaf   /**/ = Arabic::Tashkil::Dammatan,
		TashkeelKasreh      /**/ = Arabic::Tashkil::Kasra,
		TashkeelTanvinJarr  /**/ = Arabic::Tashkil::Kasratan,
		TashkeelSokoon      /**/ = Arabic::Tashkil::Sukun,
		TashkeelTashdid     /**/ = Arabic::Tashkil::Shadda,

		TashkilAlefKhanjara /**/ = Arabic::Tashkil::Khanjaria,

		TashkeelKha         /**/ = Arabic::Tashkil::SmallHighDotlessHeadOfKha,
	};

	enum class AlphabetNamesEXT : uint32_t {
		AlefHamzehAbove /**/ = Arabic::Alphabet::AlefHamzaAbove,
		AlefMadAbove    /**/ = Arabic::AlefMaddahAbove,
		Hamzeh          /**/ = Arabic::Hamza,
		VaavHamzehAbove /**/ = Arabic::Alphabet::WawHamzaAbove,
		AlefHamzehBelow /**/ = Arabic::Alphabet::AlefHamzaBelow,
		YehHamzehAbove  /**/ = Arabic::Alphabet::YehHamzaAbove,
		TehTanis        /**/ = Arabic::Alphabet::TehMarbuta,
		Seh             /**/ = Arabic::Alphabet::Theh,
		HehJeemy        /**/ = Arabic::Alphabet::Heth,
		Zaal            /**/ = Arabic::Alphabet::Thaal,
		Zeh             /**/ = Arabic::Alphabet::Zain,
		Zaad            /**/ = Arabic::Alphabet::Daad,
		Vaav            /**/ = Arabic::Alphabet::Waw
	};
	// ReSharper restore CommentTypo, IdentifierTypo
}