import os
import shutil
import logging

# ================= 配置区域 =================

# 1. 你的原始数据集路径（即你刚才 ls 看到的那个文件夹）
SOURCE_DIR = '/root/data/ISCX-VPN-2016/filtered/Raw/' 

# 2. 整理后的输出路径（脚本会自动创建这个文件夹）
TARGET_DIR = '/root/data/ISCX-VPN-2016/filtered/tmp/'

# 3. 定义类别关键字映射
# 键(Key)是目标文件夹名称，值(Value)是文件名中包含的关键字列表
# 这里的列表基于你提供的 split_based_flow.ipynb 中的 datasets_class_name
CLASS_MAPPING = {
    'aim': ['aim'],
    'email': ['email'],
    'facebook': ['facebook'],
    'sftp': ['sftp'],
    'gmail': ['gmail'],
    'hangout': ['hangout'],
    'icq': ['icq'],
    'netflix': ['netflix'],
    'scp': ['scp'],
    'ftp': ['ftp', 'ftps'], # ftps 也归类为 ftp
    'skype': ['skype'],
    'spotify': ['spotify'],
    'vimeo': ['vimeo'],
    'torrent': ['torrent', 'bittorrent'],
    'voipbuster': ['voipbuster'],
    'youtube': ['youtube']
}

# ===========================================

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )

def organize_files():
    setup_logging()
    
    if not os.path.exists(SOURCE_DIR):
        logging.error(f"源目录不存在: {SOURCE_DIR}")
        return

    # 创建目标根目录
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)
        logging.info(f"创建目标目录: {TARGET_DIR}")

    # 获取源目录下的所有文件
    files = [f for f in os.listdir(SOURCE_DIR) if os.path.isfile(os.path.join(SOURCE_DIR, f))]
    
    count_moved = 0
    count_skipped = 0

    for filename in files:
        # 忽略非 pcap 文件 (可选)
        if not (filename.endswith('.pcap') or filename.endswith('.pcapng')):
            continue

        matched_class = None
        filename_lower = filename.lower()

        # 遍历映射规则进行匹配
        for class_name, keywords in CLASS_MAPPING.items():
            for keyword in keywords:
                if keyword in filename_lower:
                    matched_class = class_name
                    break
            if matched_class:
                break
        
        # 如果匹配到了类别
        if matched_class:
            # 创建类别子文件夹
            class_dir = os.path.join(TARGET_DIR, matched_class)
            os.makedirs(class_dir, exist_ok=True)

            # 构建源路径和目标路径
            src_path = os.path.join(SOURCE_DIR, filename)
            dst_path = os.path.join(class_dir, filename)

            # 复制文件 (使用 copy 而不是 move，防止数据丢失，确认无误后可手动删除源文件)
            try:
                shutil.copy2(src_path, dst_path)
                logging.info(f"复制: {filename} -> {matched_class}/")
                count_moved += 1
            except Exception as e:
                logging.error(f"复制失败 {filename}: {e}")
        else:
            logging.warning(f"未匹配到类别，跳过: {filename}")
            # 可选：移动到 'unknown' 文件夹
            # unknown_dir = os.path.join(TARGET_DIR, 'unknown')
            # os.makedirs(unknown_dir, exist_ok=True)
            # shutil.copy2(os.path.join(SOURCE_DIR, filename), os.path.join(unknown_dir, filename))
            count_skipped += 1

    logging.info("="*30)
    logging.info(f"整理完成!")
    logging.info(f"成功处理文件数: {count_moved}")
    logging.info(f"未匹配文件数: {count_skipped}")
    logging.info(f"新数据集位置: {TARGET_DIR}")

if __name__ == '__main__':
    organize_files()