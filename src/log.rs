use chrono::Local;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};
use std::thread;

pub struct SizeRotatingAppender {
    directory: String,
    prefix: String,
    max_size_bytes: u64,
    current_file: Option<File>,
    current_file_path: PathBuf,
}

impl SizeRotatingAppender {
    /// max_size_bytes: 文件大小阈值，例如 10 * 1024 * 1024 (10MB)
    pub fn new(directory: &str, prefix: &str, max_size_bytes: u64) -> Self {
        // 确保目录存在
        if !Path::new(directory).exists() {
            let _ = fs::create_dir_all(directory);
        }

        Self {
            directory: directory.to_string(),
            prefix: prefix.to_string(),
            max_size_bytes,
            current_file: None,
            current_file_path: PathBuf::new(),
        }
    }

    /// 获取当前应该写入的文件路径
    /// 格式：directory/prefix.YYYY-MM-DD.log
    fn get_active_file_path(&self) -> PathBuf {
        let date = Local::now().format("%Y-%m-%d").to_string();
        Path::new(&self.directory).join(format!("{}.{}.log", self.prefix, date))
    }

    /// 执行轮转：重命名 -> 开新文件 -> 后台压缩
    fn rotate(&mut self) -> io::Result<()> {
        // 1. 关闭当前文件句柄 (非常重要，否则Windows下无法重命名，Linux下也会有句柄泄露风险)
        self.current_file = None;

        // 2. 准备归档文件名： prefix.YYYY-MM-DD.HH-MM-SS.log
        // 加上时分秒是为了防止一天内多次轮转导致文件名冲突
        let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
        let archive_filename = format!("{}.{}.log", self.prefix, timestamp);
        let archive_path = Path::new(&self.directory).join(&archive_filename);

        // 3. 重命名当前文件 (mv active.log -> archive.log)
        if self.current_file_path.exists() {
            fs::rename(&self.current_file_path, &archive_path)?;
        }

        // 4. 启动后台线程进行压缩 (以免阻塞日志写入)
        thread::spawn(move || {
            if let Err(e) = compress_file(&archive_path) {
                eprintln!("日志压缩失败: {:?} - {}", archive_path, e);
            }
        });

        Ok(())
    }

    /// 打开或创建日志文件
    fn open_file(&mut self) -> io::Result<()> {
        let path = self.get_active_file_path();

        // 如果文件名变了（比如跨天了），或者文件还没打开
        if self.current_file.is_none() || path != self.current_file_path {
            self.current_file_path = path.clone();
            let file = OpenOptions::new().create(true).append(true).open(&path)?;
            self.current_file = Some(file);
        }
        Ok(())
    }
}

/// 独立的压缩函数：读取源文件 -> 写入 .gz -> 删除源文件
fn compress_file(source_path: &Path) -> io::Result<()> {
    let source_file = File::open(source_path)?;
    let mut reader = BufReader::new(source_file);

    // 目标文件：source.gz
    let mut dest_path = source_path.to_path_buf();
    if let Some(ext) = dest_path.extension() {
        let mut new_ext = ext.to_os_string();
        new_ext.push(".gz");
        dest_path.set_extension(new_ext);
    } else {
        dest_path.set_extension("gz");
    }

    let dest_file = File::create(&dest_path)?;
    let mut encoder = GzEncoder::new(dest_file, Compression::default());

    // 执行流式压缩
    io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?;

    // 压缩成功后，删除原始的未压缩文件
    fs::remove_file(source_path)?;

    Ok(())
}

impl Write for SizeRotatingAppender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // 1. 确保文件已打开
        self.open_file()?;

        // 2. 检查文件大小
        if let Some(file) = &self.current_file {
            let metadata = file.metadata()?;
            if metadata.len() + buf.len() as u64 > self.max_size_bytes {
                // 3. 如果超出大小，执行轮转
                self.rotate()?;
                // 轮转后重新打开新文件
                self.open_file()?;
            }
        }

        // 4. 写入数据
        if let Some(file) = &mut self.current_file {
            file.write(buf)
        } else {
            Err(io::Error::other("无法打开日志文件"))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = &mut self.current_file {
            file.flush()
        } else {
            Ok(())
        }
    }
}
