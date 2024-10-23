import { diskStorage } from 'multer';

export const storageConfig = (folder: string) =>
  diskStorage({
    destination: `uploads/${folder}`,
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
    // Generate unique filename with current timestamp.
    // Use original filename as it's safe and unique.
    // You can also add more validation here.
    // For example, you can check if the file type is allowed.
    // For example, you can use multer-filetype-validator middleware.
    // For example, you can use multer-file
  });
