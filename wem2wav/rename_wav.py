import os
import re

def rename_wav_files(directory):
    """
    批量重命名wav文件
    将格式如 AAL_0_35.464s_387661620.wav 重命名为 387661620.wav
    """
    # 匹配模式：提取最后的数字部分
    pattern = re.compile(r'.*_(\d+)\.wav$')

    renamed_count = 0
    skipped_count = 0
    error_count = 0

    print(f"开始扫描目录: {directory}")
    print("正在处理文件...")

    try:
        files = os.listdir(directory)
        total_files = len(files)
        print(f"找到 {total_files} 个文件")

        for index, filename in enumerate(files, 1):
            # 只处理wav文件
            if not filename.lower().endswith('.wav'):
                continue

            # 匹配文件名模式
            match = pattern.match(filename)
            if match:
                # 提取数字部分
                number = match.group(1)
                new_filename = f"{number}.wav"

                old_path = os.path.join(directory, filename)
                new_path = os.path.join(directory, new_filename)

                # 检查目标文件是否已存在
                if os.path.exists(new_path):
                    print(f"跳过 (目标已存在): {filename} -> {new_filename}")
                    skipped_count += 1
                    continue

                try:
                    os.rename(old_path, new_path)
                    renamed_count += 1

                    # 每处理1000个文件显示一次进度
                    if renamed_count % 1000 == 0:
                        print(f"已处理: {renamed_count} 个文件...")

                except Exception as e:
                    print(f"错误: 无法重命名 {filename}: {e}")
                    error_count += 1
            else:
                # 文件名不匹配预期格式
                if filename.lower().endswith('.wav'):
                    print(f"跳过 (格式不匹配): {filename}")
                    skipped_count += 1

    except Exception as e:
        print(f"发生错误: {e}")
        return

    print("\n" + "="*50)
    print("重命名完成!")
    print(f"成功重命名: {renamed_count} 个文件")
    print(f"跳过: {skipped_count} 个文件")
    print(f"错误: {error_count} 个文件")
    print("="*50)

if __name__ == "__main__":
    # 使用当前目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    rename_wav_files(current_dir)
