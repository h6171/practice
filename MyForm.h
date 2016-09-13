// Encrypting & decrypting messages using RSA & AES algorithms
// RSA key length (in bits) supported: 1024, 2048, 4096; AES: 128, 192, 256;

// OPENSSL 1.0.1t used
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#pragma once

namespace Students_Encryption {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;

	using namespace System::Runtime::InteropServices; // Marshal

	/// <summary>
	/// ������ ��� MyForm
	/// </summary>

	public ref class MyForm : public System::Windows::Forms::Form{
		public:
			MyForm(void)
			{
				InitializeComponent();

				// ��������� �� ���������
				m_cb_mode->SelectedIndex = 0; // �����������
				m_cb_type->SelectedIndex = 0; // ��� - AES
				m_cb_size->SelectedIndex = 0; // ���� - 128 ���
			}

		protected:
			/// <summary>
			/// ���������� ��� ������������ �������.
			/// </summary>

			~MyForm()
			{
				if (components)
				{
					delete components;
				}
			}

		private: System::Windows::Forms::Button^  m_btn;
		private: System::Windows::Forms::GroupBox^  m_gb;
		private: System::Windows::Forms::TextBox^  m_tb_msg;
		private: System::Windows::Forms::Label^  m_label_msg;
		private: System::Windows::Forms::TextBox^  m_tb_emsg;
		private: System::Windows::Forms::TextBox^  m_tb_key;
		private: System::Windows::Forms::Label^  m_label_emsg;
		private: System::Windows::Forms::ComboBox^  m_cb_type;
		private: System::Windows::Forms::ComboBox^  m_cb_size;
		private: System::Windows::Forms::Label^  m_label_mode;
		private: System::Windows::Forms::Label^  m_label_size;
		private: System::Windows::Forms::Label^  m_label_type;
		private: System::Windows::Forms::Label^  m_label_key;
		private: System::Windows::Forms::ComboBox^  m_cb_mode;




		private:
			/// <summary>
			/// ������������ ���������� ������������.
			/// </summary>
			System::ComponentModel::Container ^components;

	#pragma region Windows Form Designer generated code
			/// <summary>
			/// ��������� ����� ��� ��������� ������������ � �� ��������� 
			/// ���������� ����� ������ � ������� ��������� ����.
			/// </summary>
			void InitializeComponent(void)
			{
				this->m_btn = (gcnew System::Windows::Forms::Button());
				this->m_gb = (gcnew System::Windows::Forms::GroupBox());
				this->m_label_mode = (gcnew System::Windows::Forms::Label());
				this->m_label_size = (gcnew System::Windows::Forms::Label());
				this->m_label_type = (gcnew System::Windows::Forms::Label());
				this->m_label_key = (gcnew System::Windows::Forms::Label());
				this->m_cb_mode = (gcnew System::Windows::Forms::ComboBox());
				this->m_cb_size = (gcnew System::Windows::Forms::ComboBox());
				this->m_cb_type = (gcnew System::Windows::Forms::ComboBox());
				this->m_tb_key = (gcnew System::Windows::Forms::TextBox());
				this->m_label_emsg = (gcnew System::Windows::Forms::Label());
				this->m_tb_emsg = (gcnew System::Windows::Forms::TextBox());
				this->m_label_msg = (gcnew System::Windows::Forms::Label());
				this->m_tb_msg = (gcnew System::Windows::Forms::TextBox());
				this->m_gb->SuspendLayout();
				this->SuspendLayout();
				// 
				// m_btn
				// 
				this->m_btn->Location = System::Drawing::Point(220, 348);
				this->m_btn->Name = L"m_btn";
				this->m_btn->Size = System::Drawing::Size(96, 23);
				this->m_btn->TabIndex = 0;
				this->m_btn->Text = L"���������";
				this->m_btn->UseVisualStyleBackColor = true;
				this->m_btn->Click += gcnew System::EventHandler(this, &MyForm::m_btn_Click);
				// 
				// m_gb
				// 
				this->m_gb->Controls->Add(this->m_label_mode);
				this->m_gb->Controls->Add(this->m_label_size);
				this->m_gb->Controls->Add(this->m_label_type);
				this->m_gb->Controls->Add(this->m_label_key);
				this->m_gb->Controls->Add(this->m_cb_mode);
				this->m_gb->Controls->Add(this->m_cb_size);
				this->m_gb->Controls->Add(this->m_cb_type);
				this->m_gb->Controls->Add(this->m_tb_key);
				this->m_gb->Controls->Add(this->m_label_emsg);
				this->m_gb->Controls->Add(this->m_tb_emsg);
				this->m_gb->Controls->Add(this->m_label_msg);
				this->m_gb->Controls->Add(this->m_tb_msg);
				this->m_gb->Location = System::Drawing::Point(12, 12);
				this->m_gb->Name = L"m_gb";
				this->m_gb->Size = System::Drawing::Size(512, 324);
				this->m_gb->TabIndex = 1;
				this->m_gb->TabStop = false;
				this->m_gb->Text = L"�������� ����������� ������� � ������� �� ������";
				// 
				// m_label_mode
				// 
				this->m_label_mode->Location = System::Drawing::Point(25, 35);
				this->m_label_mode->Name = L"m_label_mode";
				this->m_label_mode->Size = System::Drawing::Size(116, 16);
				this->m_label_mode->TabIndex = 11;
				this->m_label_mode->Text = L"�������� ��������:";
				// 
				// m_label_size
				// 
				this->m_label_size->Location = System::Drawing::Point(25, 121);
				this->m_label_size->Name = L"m_label_size";
				this->m_label_size->Size = System::Drawing::Size(125, 16);
				this->m_label_size->TabIndex = 10;
				this->m_label_size->Text = L"������ ����� (����):";
				// 
				// m_label_type
				// 
				this->m_label_type->Location = System::Drawing::Point(25, 78);
				this->m_label_type->Name = L"m_label_type";
				this->m_label_type->Size = System::Drawing::Size(100, 16);
				this->m_label_type->TabIndex = 9;
				this->m_label_type->Text = L"��� ����������:";
				// 
				// m_label_key
				// 
				this->m_label_key->Location = System::Drawing::Point(12, 180);
				this->m_label_key->Name = L"m_label_key";
				this->m_label_key->Size = System::Drawing::Size(199, 16);
				this->m_label_key->TabIndex = 8;
				this->m_label_key->Text = L"���� ��� ����������� ���������:";
				// 
				// m_cb_mode
				// 
				this->m_cb_mode->DropDownStyle = System::Windows::Forms::ComboBoxStyle::DropDownList;
				this->m_cb_mode->FormattingEnabled = true;
				this->m_cb_mode->Items->AddRange(gcnew cli::array< System::Object^  >(2) { L"�����������", L"������������" });
				this->m_cb_mode->Location = System::Drawing::Point(28, 54);
				this->m_cb_mode->Name = L"m_cb_mode";
				this->m_cb_mode->Size = System::Drawing::Size(104, 21);
				this->m_cb_mode->TabIndex = 7;
				this->m_cb_mode->SelectionChangeCommitted += gcnew System::EventHandler(this, &MyForm::m_cb_mode_SelectionChangeCommitted);
				// 
				// m_cb_size
				// 
				this->m_cb_size->DropDownStyle = System::Windows::Forms::ComboBoxStyle::DropDownList;
				this->m_cb_size->FormattingEnabled = true;
				this->m_cb_size->Items->AddRange(gcnew cli::array< System::Object^  >(3) { L"128", L"192", L"256" });
				this->m_cb_size->Location = System::Drawing::Point(28, 140);
				this->m_cb_size->Name = L"m_cb_size";
				this->m_cb_size->Size = System::Drawing::Size(104, 21);
				this->m_cb_size->TabIndex = 6;
				// 
				// m_cb_type
				// 
				this->m_cb_type->DropDownStyle = System::Windows::Forms::ComboBoxStyle::DropDownList;
				this->m_cb_type->FormattingEnabled = true;
				this->m_cb_type->Items->AddRange(gcnew cli::array< System::Object^  >(2) { L"AES", L"RSA" });
				this->m_cb_type->Location = System::Drawing::Point(28, 97);
				this->m_cb_type->Name = L"m_cb_type";
				this->m_cb_type->Size = System::Drawing::Size(104, 21);
				this->m_cb_type->TabIndex = 5;
				this->m_cb_type->SelectionChangeCommitted += gcnew System::EventHandler(this, &MyForm::m_cb_type_SelectionChangeCommitted);
				// 
				// m_tb_key
				// 
				this->m_tb_key->Location = System::Drawing::Point(15, 199);
				this->m_tb_key->Multiline = true;
				this->m_tb_key->Name = L"m_tb_key";
				this->m_tb_key->ReadOnly = true;
				this->m_tb_key->ScrollBars = System::Windows::Forms::ScrollBars::Vertical;
				this->m_tb_key->Size = System::Drawing::Size(196, 102);
				this->m_tb_key->TabIndex = 3;
				this->m_tb_key->KeyDown += gcnew System::Windows::Forms::KeyEventHandler(this, &MyForm::m_tb_key_KeyDown);
				// 
				// m_label_emsg
				// 
				this->m_label_emsg->Location = System::Drawing::Point(235, 180);
				this->m_label_emsg->Name = L"m_label_emsg";
				this->m_label_emsg->Size = System::Drawing::Size(259, 18);
				this->m_label_emsg->TabIndex = 2;
				this->m_label_emsg->Text = L"��������� �������� ����� (� hex ����):";
				// 
				// m_tb_emsg
				// 
				this->m_tb_emsg->Location = System::Drawing::Point(238, 201);
				this->m_tb_emsg->Multiline = true;
				this->m_tb_emsg->Name = L"m_tb_emsg";
				this->m_tb_emsg->ReadOnly = true;
				this->m_tb_emsg->ScrollBars = System::Windows::Forms::ScrollBars::Vertical;
				this->m_tb_emsg->Size = System::Drawing::Size(256, 100);
				this->m_tb_emsg->TabIndex = 1;
				this->m_tb_emsg->KeyDown += gcnew System::Windows::Forms::KeyEventHandler(this, &MyForm::m_tb_emsg_KeyDown);
				// 
				// m_label_msg
				// 
				this->m_label_msg->Location = System::Drawing::Point(235, 42);
				this->m_label_msg->Name = L"m_label_msg";
				this->m_label_msg->Size = System::Drawing::Size(193, 16);
				this->m_label_msg->TabIndex = 0;
				this->m_label_msg->Text = L"������� ����� � ������� �� ������:";
				// 
				// m_tb_msg
				// 
				this->m_tb_msg->Location = System::Drawing::Point(238, 61);
				this->m_tb_msg->Multiline = true;
				this->m_tb_msg->Name = L"m_tb_msg";
				this->m_tb_msg->ScrollBars = System::Windows::Forms::ScrollBars::Vertical;
				this->m_tb_msg->Size = System::Drawing::Size(256, 100);
				this->m_tb_msg->TabIndex = 0;
				this->m_tb_msg->KeyDown += gcnew System::Windows::Forms::KeyEventHandler(this, &MyForm::m_tb_msg_KeyDown);
				// 
				// MyForm
				// 
				this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
				this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
				this->ClientSize = System::Drawing::Size(536, 381);
				this->Controls->Add(this->m_gb);
				this->Controls->Add(this->m_btn);
				this->MaximizeBox = false;
				this->Name = L"MyForm";
				this->StartPosition = System::Windows::Forms::FormStartPosition::CenterScreen;
				this->Text = L"Enc-Dec";
				this->m_gb->ResumeLayout(false);
				this->m_gb->PerformLayout();
				this->ResumeLayout(false);

			}
	#pragma endregion

		private: System::Void m_btn_Click(System::Object^  sender, System::EventArgs^  e) {
			if (!(m_tb_msg->Text->Length 
				&& m_tb_key->Text->Length|!m_cb_mode->SelectedIndex)) {
				show_error("You must fill up all the fields.");
				return;
			}

			m_gb->Enabled = false;
			m_btn->Enabled = false;
			
			if (m_cb_type->SelectedIndex) {
				if (m_cb_mode->SelectedIndex) { // ����������
					RSA *rsa = NULL; BIO *keybio;

					// ���������� �����
					char *pkey = (char*)(void*)Marshal::StringToHGlobalAnsi(m_tb_key->Text);

					keybio = BIO_new_mem_buf(pkey, -1);	// ������������� BIO

					// ������������� RSA ������ �� ������
					rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
					BIO_free(keybio);	// ������������ ������

					// ������ �����
					int ksize = RSA_size(rsa);
					
					String ^msg_str = m_tb_msg->Text;	// ���������
					String ^part_str;					// ���������
					String ^result;						// ���������

					// ������ ��� �����
					int i = 0, klimit = ksize * 2, mmax = msg_str->Length / klimit;

					// 2 hex = 1 bin -> ksize*2=hex.length
					for (i; i < mmax; i++) {
						part_str = msg_str->Substring(klimit * i, klimit);
						char *msg = (char*)(void*)Marshal::StringToHGlobalAnsi(part_str);

						// ������������� �� hex � bin
						BIGNUM *bn = new BIGNUM();
						BN_hex2bn(&bn, msg);
						BN_bn2bin(bn, (unsigned char*)msg);
						BN_free(bn);

						char *decrypt = new char[ksize];

						// �����������
						if (RSA_private_decrypt(ksize, (unsigned char*)msg, 
							(unsigned char*)decrypt, rsa, RSA_PKCS1_PADDING) == -1) break;
						else result += gcnew String(decrypt);

						// ������������ ������
						Marshal::FreeHGlobal((IntPtr)msg);
						delete[] decrypt;
					}

					// ����� ���������� ��� ���� � �������
					if (i == mmax) m_tb_emsg->Text = result;
					else show_error("Error DECrypting message! Step: " + (i + 1) + ".");

					// ������������ ������
					Marshal::FreeHGlobal((IntPtr)pkey);
					RSA_free(rsa);
				}
				else {	// ��������
					RSA *rsa = NULL;										
					rsa = RSA_generate_key(Convert::ToInt16(m_cb_size->SelectedItem), RSA_F4, NULL, NULL);
					
					int ksize = RSA_size(rsa), klimit = ksize - 11;			// ������ ����� � ����� ��� ������

					BIO *pk = BIO_new(BIO_s_mem());							// �������� ������
					PEM_write_bio_RSAPrivateKey(pk, rsa, 0, 0, 0, 0, 0);	// ������ ����� � �����
					size_t pk_len = BIO_pending(pk);						// ������ ����� ������ � pk_len

					char *pkey = new char[pk_len+1];		// ��������� ������ ��� ����
					BIO_read(pk, pkey, pk_len);				// ������ ����� � pkey
					pkey[pk_len] = '\0';					// null-terminator

					m_tb_key->Text = gcnew String(pkey);	// ������ pkey � �����
						
					BIO_free(pk);							// ������������ ������
					delete[] pkey;							//

					String ^msg_str = m_tb_msg->Text;	// ���������
					String ^part_str;					// ���������, RSA_size(rsa)-11
					String ^result;						// ���������

					// �������� �������� ��� �����
					int mmax = msg_str->Length / (klimit - 1) + 1, i = 0, border;
					if (msg_str->Length % (klimit - 1) == 0) mmax--;

					for (i; i < mmax; i++) {
						border = klimit-1;	// ok encoding anyway
						if (i == mmax - 1 && mmax > 1) border = msg_str->Length - border*i;
						else if (i == mmax - 1) border = msg_str->Length;

						part_str = msg_str->Substring((klimit-1)*i, border);
						unsigned char *msg = (unsigned char*)(void*)Marshal::StringToHGlobalAnsi(part_str);

						// ��������� ������ ��� ������������� �����
						char *encrypt = new char[ksize];

						// ���������� ��������� ���������� PKCS1
						// ��� ���� �������� ����� ����� �� ������, ��� RSA_size(rsa)-11
						// ���������� �����, � ���� �������, �������� ������ = RSA_size(rsa)

						if (RSA_public_encrypt(klimit, msg,
							(unsigned char*)encrypt, rsa, RSA_PKCS1_PADDING) == -1) break;
						else {
							BIGNUM *bn = BN_new();							// �������� bn
							BN_bin2bn((unsigned char*)encrypt, ksize, bn);	// bin � bn
							encrypt = BN_bn2hex(bn);						// bn � hex
							BN_free(bn);									// ������������ ������

							result += gcnew String(encrypt);				// ������ ����������
						}

						// ������������ ������
						Marshal::FreeHGlobal((IntPtr)msg);
						delete[] encrypt;
					}

					if (i == mmax) m_tb_emsg->Text = result;
					else show_error("Error ENCrypting message! Step: " + (i + 1) + ".");

					// ������������ ������
					RSA_free(rsa);
				}
			}
			else { // AES
				if (m_cb_mode->SelectedIndex) { // ����������
					BIGNUM *bn = new BIGNUM();
					char *rand_key = (char*)(void*)Marshal::StringToHGlobalAnsi(m_tb_key->Text);

					// ������ ����� �����
					int ksize = m_tb_key->Text->Length / 2; // hex = 2*bin

					// ������������� �� hex � bin
					BN_hex2bn(&bn, rand_key);
					BN_bn2bin(bn, (unsigned char*)rand_key);

					AES_KEY aes_key;

					// ksize � �����, � �� � ������ (x8)
					if (AES_set_decrypt_key((unsigned char*)rand_key, ksize*8, &aes_key) == -1) {
						show_error("Error, invalid key.");
						return;
					}

					String ^msg_str = m_tb_msg->Text;
					String ^part_str, ^result;

					int mmax = msg_str->Length / 32;

					for (int i = 0; i < mmax; i++) {
						part_str = msg_str->Substring(32*i, 32);
						char *msg = (char*)(void*)Marshal::StringToHGlobalAnsi(part_str);

						// ������������� �� hex � bin
						BN_hex2bn(&bn, msg);
						BN_bn2bin(bn, (unsigned char*)msg);

						// ������ �������������� ���� - �� 16 ��������
						char *out = new char[16+1];

						// ����������� ���������
						AES_decrypt((unsigned char*)msg, (unsigned char*)out, &aes_key);

						out[16] = '\0'; // null-terminator
						result += gcnew String(out);

						// ������������ ������
						Marshal::FreeHGlobal((IntPtr)msg);
						delete[] out;
					}

					m_tb_emsg->Text = result;

					// ������������ ������
					BN_free(bn);
					Marshal::FreeHGlobal((IntPtr)rand_key);
				}
				else {	// ��������
					BIGNUM *bn = BN_new();
					int ksize = Convert::ToInt16(m_cb_size->SelectedItem)/8;

					// ��������� �����
					unsigned char *rand_key = new unsigned char[ksize];
					if (!RAND_bytes(rand_key, ksize)) {
						show_error("Error generating key...");
						return;
					}

					// bin � hex
					BN_bin2bn(rand_key, ksize, bn);
					char *hex_key = BN_bn2hex(bn);

					// ���������� ����
					m_tb_key->Text = gcnew String(hex_key);

					// ������� hex

					AES_KEY aes_key;

					// ksize � �����, � �� � ������ (x8)
					if (AES_set_encrypt_key(rand_key, ksize*8, &aes_key) == -1) {
						show_error("Error, invalid key.");
						return;
					}

					// ������������ ������
					delete[] rand_key;

					String ^msg_str = m_tb_msg->Text;	// ���������
					String ^part_str, ^result;			//

					int mmax = msg_str->Length/16+1, border;
					if (msg_str->Length % 16 == 0) mmax--;

					for (int i = 0; i < mmax; i++) {
						border = 16;
						if (i == mmax - 1 && mmax > 1) border = msg_str->Length - 16*i;
						else if (i == mmax - 1) border = msg_str->Length;

						part_str = msg_str->Substring(16*i, border);
						unsigned char *msg = (unsigned char*)(void*)Marshal::StringToHGlobalAnsi(part_str);

						// ������������� �����
						char *out = new char[16];

						// ���������� ���������
						AES_encrypt(msg, (unsigned char*)out, &aes_key);

						//bin � hex
						BN_bin2bn((unsigned char*)out, 16, bn);
						out = BN_bn2hex(bn);

						result += gcnew String(out);

						//������������ ������
						Marshal::FreeHGlobal((IntPtr)msg);
						delete[] out;
					}

					// ������ ����������
					m_tb_emsg->Text = result;

					// ������������ ������
					BN_free(bn);
				}
			}

			m_gb->Enabled = true;
			m_btn->Enabled = true;
		}

		private: System::Void m_cb_mode_SelectionChangeCommitted(System::Object^  sender, System::EventArgs^  e) {
			m_tb_key->ReadOnly = !m_cb_mode->SelectedIndex;	// ����� ��������� "������ ��� ������"
			m_cb_size->Enabled = !m_cb_mode->SelectedIndex; // ��������� size-����
		}
	
		private: System::Void m_cb_type_SelectionChangeCommitted(System::Object^  sender, System::EventArgs^  e) {
			m_cb_size->Items->Clear();			// �������� ���������

			if (m_cb_type->SelectedIndex) {		// ���������� �����
				m_cb_size->Items->Add("1024");
				m_cb_size->Items->Add("2048");
				m_cb_size->Items->Add("4096");
			}
			else {
				m_cb_size->Items->Add("128");
				m_cb_size->Items->Add("192");
				m_cb_size->Items->Add("256");
			}									// ...

			m_cb_size->SelectedIndex = 0;		// ����� �� ���������
		}

		private: void show_error(String^ msg) {
			MessageBox::Show(msg, "Enc-Dec", MessageBoxButtons::OK, MessageBoxIcon::Error);
		}

		private: System::Void m_tb_msg_KeyDown(System::Object^  sender, System::Windows::Forms::KeyEventArgs^  e) {
			if (e->Control && e->KeyCode == Keys::A) m_tb_msg->SelectAll();
		}

		private: System::Void m_tb_key_KeyDown(System::Object^  sender, System::Windows::Forms::KeyEventArgs^  e) {
			if (e->Control && e->KeyCode == Keys::A) m_tb_key->SelectAll();
		}

		private: System::Void m_tb_emsg_KeyDown(System::Object^  sender, System::Windows::Forms::KeyEventArgs^  e) {
			if (e->Control && e->KeyCode == Keys::A) m_tb_emsg->SelectAll();
		}
};
}
